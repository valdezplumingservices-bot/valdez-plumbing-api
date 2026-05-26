require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
app.use(cors());
app.use(express.json());

// Database connection with better error handling
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000,
});

pool.on('error', (err) => {
    console.error('Unexpected database error:', err);
});

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    console.error('ERROR: JWT_SECRET environment variable is required');
    process.exit(1);
}

// Middleware
const authenticate = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'No token provided' });
        }
        
        const token = authHeader.replace('Bearer ', '');
        const decoded = jwt.verify(token, JWT_SECRET);
        
        const userResult = await pool.query('SELECT * FROM users WHERE id = $1', [decoded.userId]);
        if (!userResult.rows[0]) {
            return res.status(401).json({ error: 'User not found' });
        }
        
        req.user = userResult.rows[0];
        next();
    } catch (err) {
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Token expired' });
        }
        res.status(401).json({ error: 'Invalid token' });
    }
};

const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
};

// Auth Routes
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password required' });
        }
        
        const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase().trim()]);
        const user = userResult.rows[0];
        
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const valid = await bcrypt.compare(password, user.password_hash);
        if (!valid) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const token = jwt.sign(
            { 
                userId: user.id, 
                role: user.role, 
                employeeId: user.employee_id, 
                companyId: user.company_id 
            },
            JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        res.json({ 
            token, 
            role: user.role, 
            email: user.email,
            name: user.name 
        });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Login failed' });
    }
});

app.get('/api/auth/me', authenticate, async (req, res) => {
    try {
        const user = { ...req.user };
        delete user.password_hash;
        
        let employee = null;
        if (user.employee_id) {
            const empResult = await pool.query('SELECT id, name, email, phone, type, hourly_rate, daily_rate, overtime_rate, department, position, status FROM employees WHERE id = $1', [user.employee_id]);
            employee = empResult.rows[0] || null;
        }
        
        res.json({ ...user, employee });
    } catch (err) {
        console.error('Auth me error:', err);
        res.status(500).json({ error: err.message });
    }
});

// Employee Routes
app.get('/api/employees', authenticate, requireAdmin, async (req, res) => {
    try {
        const { rows } = await pool.query(
            'SELECT id, name, email, phone, type, hourly_rate, daily_rate, overtime_rate, department, position, hired_date, status FROM employees WHERE company_id = $1 ORDER BY name', 
            [req.user.company_id]
        );
        res.json(rows);
    } catch (err) {
        console.error('Get employees error:', err);
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/employees', authenticate, requireAdmin, async (req, res) => {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        
        const { name, email, phone, type, hourly_rate, daily_rate, overtime_rate, department, position, hired_date } = req.body;
        
        if (!name || !email) {
            return res.status(400).json({ error: 'Name and email are required' });
        }
        
        // Create employee
        const empResult = await client.query(
            `INSERT INTO employees (company_id, name, email, phone, type, hourly_rate, daily_rate, overtime_rate, department, position, hired_date, status) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING *`,
            [req.user.company_id, name, email, phone || null, type || 'hourly', hourly_rate || 0, daily_rate || 0, overtime_rate || 0, department || null, position || null, hired_date || new Date().toISOString().split('T')[0], 'active']
        );
        
        const employee = empResult.rows[0];
        
        // Create user account for employee
        const tempPassword = Math.random().toString(36).slice(-8);
        const hashedPassword = await bcrypt.hash(tempPassword, 10);
        
        await client.query(
            `INSERT INTO users (company_id, employee_id, email, password_hash, name, role) 
             VALUES ($1, $2, $3, $4, $5, $6)`,
            [req.user.company_id, employee.id, email.toLowerCase().trim(), hashedPassword, name, 'employee']
        );
        
        await client.query('COMMIT');
        
        res.status(201).json({ 
            ...employee, 
            temp_password: tempPassword // Send this securely in production
        });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Create employee error:', err);
        res.status(500).json({ error: err.message });
    } finally {
        client.release();
    }
});

app.put('/api/employees/:id', authenticate, requireAdmin, async (req, res) => {
    try {
        const { name, email, phone, type, hourly_rate, daily_rate, overtime_rate, department, position, status } = req.body;
        
        const { rows } = await pool.query(
            `UPDATE employees SET name=$1, email=$2, phone=$3, type=$4, hourly_rate=$5, daily_rate=$6, overtime_rate=$7, department=$8, position=$9, status=$10 
             WHERE id=$11 AND company_id=$12 RETURNING *`,
            [name, email, phone, type, hourly_rate, daily_rate, overtime_rate, department, position, status, req.params.id, req.user.company_id]
        );
        
        if (rows.length === 0) {
            return res.status(404).json({ error: 'Employee not found' });
        }
        
        res.json(rows[0]);
    } catch (err) {
        console.error('Update employee error:', err);
        res.status(500).json({ error: err.message });
    }
});

// ===== CLOCK IN/OUT - FIXED VERSION =====

// Get current clock status for any employee (admin) or self (employee)
app.get('/api/clock/status', authenticate, async (req, res) => {
    try {
        let employeeId = req.query.employee_id;
        
        // Employees can only check their own status
        if (req.user.role === 'employee') {
            employeeId = req.user.employee_id;
        }
        
        if (!employeeId) {
            return res.status(400).json({ error: 'Employee ID required' });
        }
        
        // Get active entry (not clocked out)
        const activeResult = await pool.query(
            `SELECT t.*, e.name as employee_name 
             FROM time_entries t 
             JOIN employees e ON t.employee_id = e.id 
             WHERE t.employee_id = $1 AND t.clock_out IS NULL 
             ORDER BY t.clock_in DESC 
             LIMIT 1`,
            [employeeId]
        );
        
        // Get today's entries
        const today = new Date().toISOString().split('T')[0];
        const todayResult = await pool.query(
            `SELECT * FROM time_entries 
             WHERE employee_id = $1 AND entry_date = $2 
             ORDER BY clock_in DESC`,
            [employeeId, today]
        );
        
        res.json({
            is_clocked_in: activeResult.rows.length > 0,
            active_entry: activeResult.rows[0] || null,
            today_entries: todayResult.rows,
            employee_id: employeeId
        });
    } catch (err) {
        console.error('Clock status error:', err);
        res.status(500).json({ error: err.message });
    }
});

// Clock In
app.post('/api/clock/in', authenticate, async (req, res) => {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        
        let employeeId = req.body.employee_id;
        
        // Employees can only clock themselves in
        if (req.user.role === 'employee') {
            employeeId = req.user.employee_id;
        }
        
        if (!employeeId) {
            return res.status(400).json({ error: 'Employee ID required' });
        }
        
        // Verify employee belongs to company
        const empCheck = await client.query(
            'SELECT * FROM employees WHERE id = $1 AND company_id = $2',
            [employeeId, req.user.company_id]
        );
        
        if (empCheck.rows.length === 0) {
            return res.status(403).json({ error: 'Employee not found or access denied' });
        }
        
        // Check if already clocked in
        const activeCheck = await client.query(
            'SELECT * FROM time_entries WHERE employee_id = $1 AND clock_out IS NULL',
            [employeeId]
        );
        
        if (activeCheck.rows.length > 0) {
            return res.status(400).json({ 
                error: 'Already clocked in',
                active_entry: activeCheck.rows[0]
            });
        }
        
        const now = new Date();
        const entryDate = now.toISOString().split('T')[0];
        
        const { rows } = await client.query(
            `INSERT INTO time_entries (employee_id, entry_date, clock_in, status, notes) 
             VALUES ($1, $2, $3, $4, $5) RETURNING *`,
            [employeeId, entryDate, now, 'active', req.body.notes || null]
        );
        
        await client.query('COMMIT');
        
        res.json({
            success: true,
            message: 'Clocked in successfully',
            entry: rows[0]
        });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Clock in error:', err);
        res.status(500).json({ error: 'Clock in failed' });
    } finally {
        client.release();
    }
});

// Clock Out - FIXED: Now finds active entry automatically if no entry_id provided
app.post('/api/clock/out', authenticate, async (req, res) => {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        
        let employeeId = req.body.employee_id;
        let entryId = req.body.entry_id;
        
        // Employees can only clock themselves out
        if (req.user.role === 'employee') {
            employeeId = req.user.employee_id;
        }
        
        if (!employeeId) {
            return res.status(400).json({ error: 'Employee ID required' });
        }
        
        // If no entry_id provided, find the active entry for this employee
        if (!entryId) {
            const activeResult = await client.query(
                `SELECT * FROM time_entries 
                 WHERE employee_id = $1 AND clock_out IS NULL 
                 ORDER BY clock_in DESC 
                 LIMIT 1`,
                [employeeId]
            );
            
            if (activeResult.rows.length === 0) {
                return res.status(400).json({ error: 'No active clock-in found for this employee' });
            }
            
            entryId = activeResult.rows[0].id;
        }
        
        // Verify the entry exists and belongs to the right employee/company
        const entryResult = await client.query(
            `SELECT t.*, e.company_id 
             FROM time_entries t 
             JOIN employees e ON t.employee_id = e.id 
             WHERE t.id = $1`,
            [entryId]
        );
        
        const entry = entryResult.rows[0];
        
        if (!entry) {
            return res.status(404).json({ error: 'Entry not found' });
        }
        
        if (entry.company_id !== req.user.company_id) {
            return res.status(403).json({ error: 'Access denied' });
        }
        
        if (entry.clock_out) {
            return res.status(400).json({ error: 'Already clocked out' });
        }
        
        const now = new Date();
        const clockIn = new Date(entry.clock_in);
        const totalMs = now - clockIn;
        const totalHours = totalMs / 3600000;
        const regularHours = Math.min(8, totalHours);
        const overtimeHours = Math.max(0, totalHours - 8);
        
        const { rows } = await client.query(
            `UPDATE time_entries 
             SET clock_out = $1, 
                 regular_hours = $2, 
                 overtime_hours = $3, 
                 total_hours = $4, 
                 status = $5,
                 notes = COALESCE($6, notes)
             WHERE id = $7 
             RETURNING *`,
            [
                now, 
                parseFloat(regularHours.toFixed(2)), 
                parseFloat(overtimeHours.toFixed(2)), 
                parseFloat(totalHours.toFixed(2)), 
                'completed',
                req.body.notes || null,
                entryId
            ]
        );
        
        await client.query('COMMIT');
        
        res.json({
            success: true,
            message: 'Clocked out successfully',
            entry: rows[0],
            duration: {
                hours: parseFloat(totalHours.toFixed(2)),
                regular: parseFloat(regularHours.toFixed(2)),
                overtime: parseFloat(overtimeHours.toFixed(2))
            }
        });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Clock out error:', err);
        res.status(500).json({ error: 'Clock out failed' });
    } finally {
        client.release();
    }
});

// Get all time entries (timesheets)
app.get('/api/timesheets', authenticate, async (req, res) => {
    try {
        let query = `
            SELECT t.*, e.name as employee_name 
            FROM time_entries t 
            JOIN employees e ON t.employee_id = e.id 
            WHERE e.company_id = $1
        `;
        let params = [req.user.company_id];
        let paramCount = 1;
        
        // Filter by employee
        if (req.query.employee_id) {
            paramCount++;
            query += ` AND t.employee_id = $${paramCount}`;
            params.push(req.query.employee_id);
        }
        
        // Filter by date range
        if (req.query.start_date) {
            paramCount++;
            query += ` AND t.entry_date >= $${paramCount}`;
            params.push(req.query.start_date);
        }
        
        if (req.query.end_date) {
            paramCount++;
            query += ` AND t.entry_date <= $${paramCount}`;
            params.push(req.query.end_date);
        }
        
        // Employees only see their own
        if (req.user.role === 'employee') {
            paramCount++;
            query += ` AND t.employee_id = $${paramCount}`;
            params.push(req.user.employee_id);
        }
        
        query += ' ORDER BY t.entry_date DESC, t.clock_in DESC';
        
        const { rows } = await pool.query(query, params);
        res.json(rows);
    } catch (err) {
        console.error('Timesheets error:', err);
        res.status(500).json({ error: err.message });
    }
});

// Payroll Routes
app.get('/api/payroll', authenticate, async (req, res) => {
    try {
        const { start, end } = req.query;
        if (!start || !end) {
            return res.status(400).json({ error: 'Start and end dates required (YYYY-MM-DD)' });
        }
        
        if (req.user.role === 'employee') {
            const empResult = await pool.query('SELECT * FROM employees WHERE id = $1', [req.user.employee_id]);
            const emp = empResult.rows[0];
            
            if (!emp) {
                return res.status(404).json({ error: 'Employee not found' });
            }
            
            const entriesResult = await pool.query(
                `SELECT * FROM time_entries 
                 WHERE employee_id = $1 AND entry_date BETWEEN $2 AND $3 AND status = $4`,
                [req.user.employee_id, start, end, 'completed']
            );
            
            let regularPay = 0, otPay = 0, totalHours = 0;
            entriesResult.rows.forEach(e => {
                totalHours += e.total_hours;
                if (emp.type === 'hourly') {
                    regularPay += e.regular_hours * emp.hourly_rate;
                    otPay += e.overtime_hours * emp.overtime_rate;
                } else {
                    regularPay += emp.daily_rate;
                    otPay += e.overtime_hours * emp.overtime_rate;
                }
            });
            
            res.json({
                employee: emp.name,
                period: { start, end },
                regular_pay: parseFloat(regularPay.toFixed(2)),
                overtime_pay: parseFloat(otPay.toFixed(2)),
                total_pay: parseFloat((regularPay + otPay).toFixed(2)),
                total_hours: parseFloat(totalHours.toFixed(2)),
                entries_count: entriesResult.rows.length
            });
        } else {
            const employeesResult = await pool.query(
                'SELECT * FROM employees WHERE company_id = $1 AND status = $2', 
                [req.user.company_id, 'active']
            );
            
            const payroll = [];
            for (const emp of employeesResult.rows) {
                const entriesResult = await pool.query(
                    `SELECT * FROM time_entries 
                     WHERE employee_id = $1 AND entry_date BETWEEN $2 AND $3 AND status = $4`,
                    [emp.id, start, end, 'completed']
                );
                
                let regularPay = 0, otPay = 0, totalHours = 0;
                entriesResult.rows.forEach(e => {
                    totalHours += e.total_hours;
                    if (emp.type === 'hourly') {
                        regularPay += e.regular_hours * emp.hourly_rate;
                        otPay += e.overtime_hours * emp.overtime_rate;
                    } else {
                        regularPay += emp.daily_rate;
                        otPay += e.overtime_hours * emp.overtime_rate;
                    }
                });
                
                payroll.push({
                    employee_id: emp.id,
                    employee_name: emp.name,
                    employee_type: emp.type,
                    regular_pay: parseFloat(regularPay.toFixed(2)),
                    overtime_pay: parseFloat(otPay.toFixed(2)),
                    total_pay: parseFloat((regularPay + otPay).toFixed(2)),
                    total_hours: parseFloat(totalHours.toFixed(2)),
                    entries_count: entriesResult.rows.length
                });
            }
            
            res.json({
                period: { start, end },
                total_regular_pay: parseFloat(payroll.reduce((s, p) => s + p.regular_pay, 0).toFixed(2)),
                total_overtime_pay: parseFloat(payroll.reduce((s, p) => s + p.overtime_pay, 0).toFixed(2)),
                total_payroll: parseFloat(payroll.reduce((s, p) => s + p.total_pay, 0).toFixed(2)),
                total_hours: parseFloat(payroll.reduce((s, p) => s + p.total_hours, 0).toFixed(2)),
                employees: payroll
            });
        }
    } catch (err) {
        console.error('Payroll error:', err);
        res.status(500).json({ error: err.message });
    }
});

// Call-Ins Routes
app.get('/api/callins', authenticate, async (req, res) => {
    try {
        let query = `
            SELECT c.*, e.name as employee_name 
            FROM call_ins c 
            JOIN employees e ON c.employee_id = e.id 
            WHERE e.company_id = $1
        `;
        let params = [req.user.company_id];
        
        if (req.user.role === 'employee') {
            query += ' AND c.employee_id = $2';
            params.push(req.user.employee_id);
        }
        
        // Filter by status
        if (req.query.status) {
            query += ` AND c.status = $${params.length + 1}`;
            params.push(req.query.status);
        }
        
        query += ' ORDER BY c.submitted_at DESC';
        
        const { rows } = await pool.query(query, params);
        res.json(rows);
    } catch (err) {
        console.error('Call-ins error:', err);
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/callins', authenticate, async (req, res) => {
    try {
        const { employee_id, absence_date, reason } = req.body;
        const actualEmployeeId = req.user.role === 'employee' ? req.user.employee_id : employee_id;
        
        if (!actualEmployeeId || !absence_date || !reason) {
            return res.status(400).json({ error: 'Employee ID, absence date, and reason are required' });
        }
        
        const { rows } = await pool.query(
            `INSERT INTO call_ins (employee_id, absence_date, reason, status, submitted_at) 
             VALUES ($1, $2, $3, $4, NOW()) RETURNING *`,
            [actualEmployeeId, absence_date, reason, 'pending']
        );
        
        res.status(201).json(rows[0]);
    } catch (err) {
        console.error('Create call-in error:', err);
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/callins/:id/approve', authenticate, requireAdmin, async (req, res) => {
    try {
        const { rows } = await pool.query(
            `UPDATE call_ins 
             SET status=$1, reviewed_at=NOW(), reviewed_by=$2 
             WHERE id=$3 RETURNING *`,
            ['approved', req.user.id, req.params.id]
        );
        
        if (rows.length === 0) {
            return res.status(404).json({ error: 'Call-in not found' });
        }
        
        res.json(rows[0]);
    } catch (err) {
        console.error('Approve call-in error:', err);
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/callins/:id/deny', authenticate, requireAdmin, async (req, res) => {
    try {
        const { rows } = await pool.query(
            `UPDATE call_ins 
             SET status=$1, reviewed_at=NOW(), reviewed_by=$2 
             WHERE id=$3 RETURNING *`,
            ['denied', req.user.id, req.params.id]
        );
        
        if (rows.length === 0) {
            return res.status(404).json({ error: 'Call-in not found' });
        }
        
        res.json(rows[0]);
    } catch (err) {
        console.error('Deny call-in error:', err);
        res.status(500).json({ error: err.message });
    }
});

// Company Routes
app.get('/api/company', authenticate, async (req, res) => {
    try {
        const { rows } = await pool.query('SELECT * FROM companies WHERE id = $1', [req.user.company_id]);
        if (rows.length === 0) {
            return res.status(404).json({ error: 'Company not found' });
        }
        res.json(rows[0]);
    } catch (err) {
        console.error('Get company error:', err);
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/company', authenticate, requireAdmin, async (req, res) => {
    try {
        const { name, address, phone, timezone } = req.body;
        
        const { rows } = await pool.query(
            'UPDATE companies SET name = $1, address = $2, phone = $3, timezone = $4 WHERE id = $5 RETURNING *', 
            [name, address, phone, timezone, req.user.company_id]
        );
        
        res.json(rows[0]);
    } catch (err) {
        console.error('Update company error:', err);
        res.status(500).json({ error: err.message });
    }
});

// Dashboard
app.get('/api/dashboard', authenticate, async (req, res) => {
    try {
        if (req.user.role === 'employee') {
            const empResult = await pool.query('SELECT * FROM employees WHERE id = $1', [req.user.employee_id]);
            const emp = empResult.rows[0];
            
            const activeResult = await pool.query(
                'SELECT * FROM time_entries WHERE employee_id = $1 AND clock_out IS NULL', 
                [req.user.employee_id]
            );
            
            const weekStart = new Date();
            weekStart.setDate(weekStart.getDate() - 7);
            
            const weekResult = await pool.query(
                `SELECT * FROM time_entries 
                 WHERE employee_id = $1 AND entry_date >= $2 AND status = $3`,
                [req.user.employee_id, weekStart.toISOString().split('T')[0], 'completed']
            );
            
            let weekHours = 0, weekPay = 0;
            weekResult.rows.forEach(e => {
                weekHours += e.total_hours;
                if (emp.type === 'hourly') {
                    weekPay += (e.regular_hours * emp.hourly_rate) + (e.overtime_hours * emp.overtime_rate);
                } else {
                    weekPay += emp.daily_rate + (e.overtime_hours * emp.overtime_rate);
                }
            });
            
            res.json({
                is_clocked_in: activeResult.rows.length > 0,
                active_entry: activeResult.rows[0] || null,
                week_hours: parseFloat(weekHours.toFixed(2)),
                week_pay: parseFloat(weekPay.toFixed(2)),
                employee: emp
            });
        } else {
            const activeResult = await pool.query(
                `SELECT t.*, e.name as employee_name 
                 FROM time_entries t 
                 JOIN employees e ON t.employee_id = e.id 
                 WHERE t.clock_out IS NULL AND e.company_id = $1`,
                [req.user.company_id]
            );
            
            const totalEmpsResult = await pool.query(
                'SELECT COUNT(*) FROM employees WHERE company_id = $1 AND status = $2', 
                [req.user.company_id, 'active']
            );
            
            const pendingCallInsResult = await pool.query(
                `SELECT c.*, e.name as employee_name 
                 FROM call_ins c 
                 JOIN employees e ON c.employee_id = e.id 
                 WHERE c.status = $1 AND e.company_id = $2`,
                ['pending', req.user.company_id]
            );
            
            // Today's stats
            const today = new Date().toISOString().split('T')[0];
            const todayEntriesResult = await pool.query(
                `SELECT COUNT(*) FROM time_entries t 
                 JOIN employees e ON t.employee_id = e.id 
                 WHERE e.company_id = $1 AND t.entry_date = $2 AND t.status = $3`,
                [req.user.company_id, today, 'completed']
            );
            
            res.json({
                active_count: activeResult.rows.length,
                total_employees: parseInt(totalEmpsResult.rows[0].count),
                pending_callins: pendingCallInsResult.rows.length,
                today_entries: parseInt(todayEntriesResult.rows[0].count),
                active_employees: activeResult.rows,
                pending_callins_list: pendingCallInsResult.rows
            });
        }
    } catch (err) {
        console.error('Dashboard error:', err);
        res.status(500).json({ error: err.message });
    }
});

// Health & Root
app.get('/', (req, res) => {
    res.json({ 
        message: 'Valdez Plumbing Services API',
        version: '1.1.0',
        status: 'running',
        endpoints: [
            'POST /api/auth/login',
            'GET /api/auth/me',
            'GET /api/employees',
            'POST /api/employees',
            'GET /api/clock/status',
            'POST /api/clock/in',
            'POST /api/clock/out',
            'GET /api/timesheets',
            'GET /api/payroll',
            'GET /api/callins',
            'POST /api/callins',
            'GET /api/dashboard',
            'GET /api/company'
        ]
    });
});

app.get('/api/health', async (req, res) => {
    try {
        await pool.query('SELECT 1');
        res.json({ 
            status: 'ok', 
            service: 'valdez-plumbing-api', 
            database: 'connected',
            timestamp: new Date().toISOString() 
        });
    } catch (err) {
        res.status(503).json({ 
            status: 'error', 
            service: 'valdez-plumbing-api', 
            database: 'disconnected',
            error: err.message 
        });
    }
});

// Error handling
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Valdez Plumbing API v1.1.0 running on port ${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});