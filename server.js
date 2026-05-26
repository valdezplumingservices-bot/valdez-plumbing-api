require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
app.use(cors());
app.use(express.json());

// PostgreSQL connection (Railway provides DATABASE_URL)
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

const JWT_SECRET = process.env.JWT_SECRET || 'valdez-plumbing-secret-2024';
const SALT_ROUNDS = 12;

// ============ AUTH MIDDLEWARE ============
const authenticate = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.replace('Bearer ', '');
        if (!token) return res.status(401).json({ error: 'No token provided' });
        
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await pool.query('SELECT * FROM users WHERE id = $1', [decoded.userId]);
        if (!user.rows[0]) return res.status(401).json({ error: 'User not found' });
        
        req.user = user.rows[0];
        next();
    } catch (err) {
        res.status(401).json({ error: 'Invalid token' });
    }
};

const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
    next();
};

// ============ AUTH ROUTES ============
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (!user.rows[0]) return res.status(401).json({ error: 'Invalid credentials' });
        
        // For production: use bcrypt.compare(password, user.rows[0].password_hash)
        // For demo setup: plain password check (replace with bcrypt in production)
        const valid = await bcrypt.compare(password, user.rows[0].password_hash);
        if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
        
        const token = jwt.sign(
            { userId: user.rows[0].id, role: user.rows[0].role, employeeId: user.rows[0].employee_id, companyId: user.rows[0].company_id },
            JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        res.json({ token, role: user.rows[0].role, email: user.rows[0].email });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/auth/me', authenticate, async (req, res) => {
    try {
        const user = { ...req.user, password_hash: undefined };
        let employee = null;
        if (user.employee_id) {
            const emp = await pool.query('SELECT * FROM employees WHERE id = $1', [user.employee_id]);
            employee = emp.rows[0];
        }
        res.json({ ...user, employee });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============ EMPLOYEES (ADMIN ONLY) ============
app.get('/api/employees', authenticate, requireAdmin, async (req, res) => {
    try {
        const { rows } = await pool.query(
            'SELECT * FROM employees WHERE company_id = $1 ORDER BY name',
            [req.user.company_id]
        );
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/employees', authenticate, requireAdmin, async (req, res) => {
    try {
        const { name, email, phone, type, hourly_rate, daily_rate, overtime_rate, department, position, hired_date } = req.body;
        const client = await pool.connect();
        
        try {
            await client.query('BEGIN');
            
            const { rows: empRows } = await client.query(
                `INSERT INTO employees (company_id, name, email, phone, type, hourly_rate, daily_rate, overtime_rate, department, position, hired_date, status)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'active') RETURNING *`,
                [req.user.company_id, name, email, phone, type, hourly_rate || 0, daily_rate || 0, overtime_rate, department, position, hired_date]
            );
            
            const tempPassword = Math.random().toString(36).slice(-8);
            const hash = await bcrypt.hash(tempPassword, SALT_ROUNDS);
            
            await client.query(
                `INSERT INTO users (company_id, email, password_hash, role, employee_id)
                 VALUES ($1, $2, $3, 'employee', $4)`,
                [req.user.company_id, email, hash, empRows[0].id]
            );
            
            await client.query('COMMIT');
            res.status(201).json({ ...empRows[0], temp_password: tempPassword });
        } catch (err) {
            await client.query('ROLLBACK');
            throw err;
        } finally {
            client.release();
        }
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/employees/:id', authenticate, requireAdmin, async (req, res) => {
    try {
        const { name, email, phone, type, hourly_rate, daily_rate, overtime_rate, department, position, status } = req.body;
        const { rows } = await pool.query(
            `UPDATE employees SET name=$1, email=$2, phone=$3, type=$4, hourly_rate=$5, daily_rate=$6, 
             overtime_rate=$7, department=$8, position=$9, status=$10 WHERE id=$11 RETURNING *`,
            [name, email, phone, type, hourly_rate, daily_rate, overtime_rate, department, position, status, req.params.id]
        );
        res.json(rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/employees/:id', authenticate, requireAdmin, async (req, res) => {
    try {
        await pool.query('DELETE FROM employees WHERE id = $1', [req.params.id]);
        res.json({ deleted: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============ CLOCK IN/OUT ============
app.post('/api/clock/in', authenticate, async (req, res) => {
    try {
        let employee_id = req.body.employee_id;
        
        // Employees can only clock themselves in
        if (req.user.role === 'employee') {
            employee_id = req.user.employee_id;
        }
        
        // Verify employee exists and belongs to company
        const empCheck = await pool.query(
            'SELECT * FROM employees WHERE id = $1 AND company_id = $2',
            [employee_id, req.user.company_id]
        );
        if (!empCheck.rows[0]) return res.status(404).json({ error: 'Employee not found' });
        
        // Check if already clocked in
        const active = await pool.query(
            'SELECT * FROM time_entries WHERE employee_id = $1 AND clock_out IS NULL',
            [employee_id]
        );
        if (active.rows[0]) return res.status(400).json({ error: 'Already clocked in', entry: active.rows[0] });
        
        const now = new Date();
        const { rows } = await pool.query(
            `INSERT INTO time_entries (employee_id, entry_date, clock_in, status)
             VALUES ($1, $2, $3, 'active') RETURNING *`,
            [employee_id, now.toISOString().split('T')[0], now]
        );
        
        res.json(rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/clock/out', authenticate, async (req, res) => {
    try {
        const { entry_id } = req.body;
        
        // Get entry and verify ownership
        const entry = await pool.query(
            'SELECT * FROM time_entries WHERE id = $1',
            [entry_id]
        );
        if (!entry.rows[0]) return res.status(404).json({ error: 'Entry not found' });
        
        // Employees can only clock themselves out
        if (req.user.role === 'employee' && entry.rows[0].employee_id !== req.user.employee_id) {
            return res.status(403).json({ error: 'Not your entry' });
        }
        
        const now = new Date();
        const clockIn = new Date(entry.rows[0].clock_in);
        const totalHours = (now - clockIn) / 3600000;
        const regularHours = Math.min(8, totalHours);
        const overtimeHours = Math.max(0, totalHours - 8);
        
        const { rows } = await pool.query(
            `UPDATE time_entries SET clock_out=$1, regular_hours=$2, overtime_hours=$3, total_hours=$4, status='completed'
             WHERE id=$5 RETURNING *`,
            [now, parseFloat(regularHours.toFixed(2)), parseFloat(overtimeHours.toFixed(2)), parseFloat(totalHours.toFixed(2)), entry_id]
        );
        
        res.json(rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/clock/active', authenticate, async (req, res) => {
    try {
        let query = `
            SELECT t.*, e.name, e.type, e.hourly_rate, e.daily_rate, e.overtime_rate, e.department, e.position
            FROM time_entries t
            JOIN employees e ON t.employee_id = e.id
            WHERE t.clock_out IS NULL
        `;
        let params = [];
        
        if (req.user.role === 'employee') {
            query += ' AND t.employee_id = $1';
            params = [req.user.employee_id];
        }
        
        const { rows } = await pool.query(query, params);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============ TIMESHEETS (ROLE-BASED) ============
app.get('/api/timesheets', authenticate, async (req, res) => {
    try {
        let query = `
            SELECT t.*, e.name as employee_name, e.type, e.hourly_rate, e.daily_rate, e.overtime_rate
            FROM time_entries t
            JOIN employees e ON t.employee_id = e.id
            WHERE e.company_id = $1
        `;
        let params = [req.user.company_id];
        
        if (req.user.role === 'employee') {
            query += ' AND t.employee_id = $2';
            params.push(req.user.employee_id);
        }
        
        if (req.query.start && req.query.end) {
            query += ` AND t.entry_date BETWEEN $${params.length + 1} AND $${params.length + 2}`;
            params.push(req.query.start, req.query.end);
        }
        
        query += ' ORDER BY t.entry_date DESC, t.clock_in DESC';
        
        const { rows } = await pool.query(query, params);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/timesheets/:id', authenticate, requireAdmin, async (req, res) => {
    try {
        await pool.query('DELETE FROM time_entries WHERE id = $1', [req.params.id]);
        res.json({ deleted: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============ PAYROLL (ROLE-BASED) ============
app.get('/api/payroll', authenticate, async (req, res) => {
    try {
        const { start, end } = req.query;
        if (!start || !end) return res.status(400).json({ error: 'Start and end dates required' });
        
        if (req.user.role === 'employee') {
            // Employee: only their own pay
            const { rows: empRows } = await pool.query(
                'SELECT * FROM employees WHERE id = $1',
                [req.user.employee_id]
            );
            const emp = empRows[0];
            
            const { rows: entries } = await pool.query(`
                SELECT * FROM time_entries 
                WHERE employee_id = $1 AND entry_date BETWEEN $2 AND $3 AND status = 'completed'
            `, [req.user.employee_id, start, end]);
            
            let regularPay = 0, otPay = 0, regularHours = 0, otHours = 0;
            entries.forEach(e => {
                regularHours += e.regular_hours;
                otHours += e.overtime_hours;
                if (emp.type === 'hourly') {
                    regularPay += e.regular_hours * emp.hourly_rate;
                    otPay += e.overtime_hours * emp.overtime_rate;
                } else {
                    regularPay += emp.daily_rate;
                    otPay += e.overtime_hours * emp.overtime_rate;
                }
            });
            
            res.json({
                employee: { name: emp.name, type: emp.type, position: emp.position },
                period: { start, end },
                regular_hours: regularHours,
                overtime_hours: otHours,
                regular_pay: parseFloat(regularPay.toFixed(2)),
                overtime_pay: parseFloat(otPay.toFixed(2)),
                total_pay: parseFloat((regularPay + otPay).toFixed(2)),
                shifts: entries.length,
                entries
            });
        } else {
            // Admin: all employees
            const { rows: employees } = await pool.query(
                'SELECT * FROM employees WHERE company_id = $1 AND status = $2 ORDER BY name',
                [req.user.company_id, 'active']
            );
            
            const payroll = [];
            let totalRegularPay = 0, totalOTPay = 0;
            
            for (const emp of employees) {
                const { rows: entries } = await pool.query(`
                    SELECT * FROM time_entries 
                    WHERE employee_id = $1 AND entry_date BETWEEN $2 AND $3 AND status = 'completed'
                `, [emp.id, start, end]);
                
                let regularPay = 0, otPay = 0, regHours = 0, otHours = 0;
                entries.forEach(e => {
                    regHours += e.regular_hours;
                    otHours += e.overtime_hours;
                    if (emp.type === 'hourly') {
                        regularPay += e.regular_hours * emp.hourly_rate;
                        otPay += e.overtime_hours * emp.overtime_rate;
                    } else {
                        regularPay += emp.daily_rate;
                        otPay += e.overtime_hours * emp.overtime_rate;
                    }
                });
                
                totalRegularPay += regularPay;
                totalOTPay += otPay;
                
                payroll.push({
                    employee: emp,
                    shifts: entries.length,
                    regular_hours: regHours,
                    overtime_hours: otHours,
                    regular_pay: parseFloat(regularPay.toFixed(2)),
                    overtime_pay: parseFloat(otPay.toFixed(2)),
                    total_pay: parseFloat((regularPay + otPay).toFixed(2))
                });
            }
            
            res.json({
                period: { start, end },
                total_regular_pay: parseFloat(totalRegularPay.toFixed(2)),
                total_overtime_pay: parseFloat(totalOTPay.toFixed(2)),
                total_payroll: parseFloat((totalRegularPay + totalOTPay).toFixed(2)),
                employee_count: employees.length,
                employees: payroll
            });
        }
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============ CALL-INS (ROLE-BASED) ============
app.get('/api/callins', authenticate, async (req, res) => {
    try {
        let query = `
            SELECT c.*, e.name as employee_name, e.position, e.department
            FROM call_ins c
            JOIN employees e ON c.employee_id = e.id
            WHERE e.company_id = $1
        `;
        let params = [req.user.company_id];
        
        if (req.user.role === 'employee') {
            query += ' AND c.employee_id = $2';
            params.push(req.user.employee_id);
        }
        
        query += ' ORDER BY c.submitted_at DESC';
        
        const { rows } = await pool.query(query, params);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/callins', authenticate, async (req, res) => {
    try {
        const { employee_id, absence_date, reason } = req.body;
        const actualEmployeeId = req.user.role === 'employee' ? req.user.employee_id : employee_id;
        
        // Verify employee belongs to company
        const empCheck = await pool.query(
            'SELECT * FROM employees WHERE id = $1 AND company_id = $2',
            [actualEmployeeId, req.user.company_id]
        );
        if (!empCheck.rows[0]) return res.status(404).json({ error: 'Employee not found' });
        
        const { rows } = await pool.query(
            `INSERT INTO call_ins (employee_id, absence_date, reason, status)
             VALUES ($1, $2, $3, 'pending') RETURNING *`,
            [actualEmployeeId, absence_date, reason]
        );
        res.status(201).json(rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/callins/:id/approve', authenticate, requireAdmin, async (req, res) => {
    try {
        const { rows } = await pool.query(
            `UPDATE call_ins SET status='approved', reviewed_at=NOW(), reviewed_by=$1 WHERE id=$2 RETURNING *`,
            [req.user.id, req.params.id]
        );
        res.json(rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/callins/:id/reject', authenticate, requireAdmin, async (req, res) => {
    try {
        const { rows } = await pool.query(
            `UPDATE call_ins SET status='rejected', reviewed_at=NOW(), reviewed_by=$1 WHERE id=$2 RETURNING *`,
            [req.user.id, req.params.id]
        );
        res.json(rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============ COMPANY SETTINGS (ADMIN) ============
app.get('/api/company', authenticate, async (req, res) => {
    try {
        const { rows } = await pool.query('SELECT * FROM companies WHERE id = $1', [req.user.company_id]);
        res.json(rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/company', authenticate, requireAdmin, async (req, res) => {
    try {
        const { name } = req.body;
        const { rows } = await pool.query(
            'UPDATE companies SET name = $1 WHERE id = $2 RETURNING *',
            [name, req.user.company_id]
        );
        res.json(rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============ DASHBOARD (ROLE-BASED) ============
app.get('/api/dashboard', authenticate, async (req, res) => {
    try {
        const today = new Date().toISOString().split('T')[0];
        
        if (req.user.role === 'employee') {
            // Employee dashboard
            const { rows: activeEntry } = await pool.query(
                'SELECT * FROM time_entries WHERE employee_id = $1 AND clock_out IS NULL',
                [req.user.employee_id]
            );
            
            const weekStart = new Date();
            weekStart.setDate(weekStart.getDate() - 7);
            
            const { rows: weekEntries } = await pool.query(
                `SELECT * FROM time_entries 
                 WHERE employee_id = $1 AND entry_date >= $2 AND status = 'completed'
                 ORDER BY entry_date DESC`,
                [req.user.employee_id, weekStart.toISOString().split('T')[0]]
            );
            
            const { rows: empRows } = await pool.query(
                'SELECT * FROM employees WHERE id = $1',
                [req.user.employee_id]
            );
            const emp = empRows[0];
            
            const { rows: myCallIns } = await pool.query(
                `SELECT * FROM call_ins WHERE employee_id = $1 ORDER BY submitted_at DESC LIMIT 5`,
                [req.user.employee_id]
            );
            
            let weekHours = 0, weekPay = 0;
            weekEntries.forEach(e => {
                weekHours += e.total_hours;
                if (emp.type === 'hourly') {
                    weekPay += (e.regular_hours * emp.hourly_rate) + (e.overtime_hours * emp.overtime_rate);
                } else {
                    weekPay += emp.daily_rate + (e.overtime_hours * emp.overtime_rate);
                }
            });
            
            res.json({
                role: 'employee',
                employee_name: emp.name,
                is_clocked_in: activeEntry.length > 0,
                current_entry: activeEntry[0] || null,
                week_hours: parseFloat(weekHours.toFixed(2)),
                week_pay: parseFloat(weekPay.toFixed(2)),
                recent_entries: weekEntries.slice(0, 5),
                recent_callins: myCallIns,
                employee_type: emp.type,
                hourly_rate: emp.hourly_rate,
                daily_rate: emp.daily_rate,
                overtime_rate: emp.overtime_rate
            });
        } else {
            // Admin dashboard
            const { rows: active } = await pool.query(`
                SELECT t.*, e.name, e.position 
                FROM time_entries t
                JOIN employees e ON t.employee_id = e.id
                WHERE t.clock_out IS NULL AND e.company_id = $1
            `, [req.user.company_id]);
            
            const { rows: totalEmps } = await pool.query(
                'SELECT COUNT(*) FROM employees WHERE company_id = $1 AND status = $2',
                [req.user.company_id, 'active']
            );
            
            const { rows: pendingCallIns } = await pool.query(`
                SELECT c.*, e.name 
                FROM call_ins c
                JOIN employees e ON c.employee_id = e.id
                WHERE c.status = 'pending' AND e.company_id = $1
            `, [req.user.company_id]);
            
            const weekStart = new Date();
            weekStart.setDate(weekStart.getDate() - 7);
            
            const { rows: weekEntries } = await pool.query(`
                SELECT t.*, e.type, e.hourly_rate, e.daily_rate, e.overtime_rate, e.name
                FROM time_entries t
                JOIN employees e ON t.employee_id = e.id
                WHERE t.entry_date >= $1 AND t.status = 'completed' AND e.company_id = $2
            `, [weekStart.toISOString().split('T')[0], req.user.company_id]);
            
            let weekPayroll = 0;
            weekEntries.forEach(e => {
                if (e.type === 'hourly') {
                    weekPayroll += (e.regular_hours * e.hourly_rate) + (e.overtime_hours * e.overtime_rate);
                } else {
                    weekPayroll += e.daily_rate + (e.overtime_hours * e.overtime_rate);
                }
            });
            
            res.json({
                role: 'admin',
                active_count: active.length,
                total_employees: parseInt(totalEmps[0].count),
                pending_callins: pendingCallIns.length,
                week_payroll: parseFloat(weekPayroll.toFixed(2)),
                active_employees: active,
                recent_entries: weekEntries.slice(0, 5),
                pending_callin_list: pendingCallIns
            });
        }
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============ HEALTH CHECK ============
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', service: 'valdez-plumbing-api', timestamp: new Date().toISOString() });
});

// ============ ERROR HANDLER ============
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Something went wrong!' });
});

// ============ START ============
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`╔══════════════════════════════════════════════════╗`);
    console.log(`║   Valdez Plumbing Services - Workforce API       ║`);
    console.log(`║   Running on port ${PORT}                          ║`);
    console.log(`╚══════════════════════════════════════════════════╝`);
});