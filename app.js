const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const path = require('path');
const fs = require('fs').promises;
const csv = require('csv-parser');
const createCsvWriter = require('csv-writer').createObjectCsvWriter;
const multer = require('multer');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const http = require('http');
const User = require('./models/User');

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Session setup
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } // set to true if using https
}));

// Set view engine to EJS
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Path to user profile CSV
const userProfileFilePath = path.join(__dirname, 'data', 'userprofile.csv');
console.log('User profile file path:', userProfileFilePath);
const resumeUploadCsvPath = path.join(__dirname, 'resumeupload.csv');
const resumeContactsCsvPath = path.join(__dirname, 'Resumencontacts.csv');
const uploadsDir = path.join(__dirname, 'uploads');
const exportDir = path.join(__dirname, 'exports');

// Ensure directories exist
async function ensureDirExists(dir) {
    try {
        await fs.access(dir);
    } catch (error) {
        if (error.code === 'ENOENT') {
            await fs.mkdir(dir, { recursive: true });
        } else {
            throw error;
        }
    }
}

// Set up multer storage
const storage = multer.diskStorage({
    destination: async (req, file, cb) => {
        await ensureDirExists(uploadsDir);
        cb(null, uploadsDir);
    },
    filename: (req, file, cb) => {
        const uniqueName = `${Date.now()}-${file.originalname}`;
        cb(null, uniqueName);
    }
});

const upload = multer({ storage: storage });

// Helper functions
async function readUsersFromCsv() {
    const users = [];
    const fileContent = await fs.readFile(userProfileFilePath, 'utf8');
    return new Promise((resolve, reject) => {
        const stream = require('stream');
        const bufferStream = new stream.PassThrough();
        bufferStream.end(fileContent);

        bufferStream
            .pipe(csv())
            .on('data', (row) => {
                // Only add rows with non-empty email addresses
                if (row.Email && row.Email.trim() !== '') {
                    row.isUSA = row.isUSA.toLowerCase() === 'true';
                    users.push(row);
                }
            })
            .on('end', () => {
                console.log('CSV file successfully processed');
                resolve(users);
            })
            .on('error', (error) => {
                console.error('Error reading CSV:', error);
                reject(error);
            });
    });
}

async function writeUsersToCsv(users) {
    const csvWriter = createCsvWriter({
        path: userProfileFilePath,
        header: [
            {id: 'id', title: 'ID'},
            {id: 'firstName', title: 'First Name'},
            {id: 'lastName', title: 'Last Name'},
            {id: 'email', title: 'Email'},
            {id: 'password', title: 'Password'},
            {id: 'role', title: 'Role'},
            {id: 'company', title: 'Company'},
            {id: 'managerId', title: 'Manager ID'},
            {id: 'supervisorId', title: 'Supervisor ID'},
            {id: 'mobileNumber', title: 'Mobile Number'},
            {id: 'street', title: 'Street'},
            {id: 'city', title: 'City'},
            {id: 'state', title: 'State'},
            {id: 'zipCode', title: 'Zip Code'},
            {id: 'country', title: 'Country'},
            {id: 'isUSA', title: 'isUSA'}
        ]
    });

    try {
        await csvWriter.writeRecords(users);
        console.log('CSV file was written successfully');
    } catch (error) {
        console.error('Error writing CSV file:', error);
        throw error;
    }
}

async function readUploadsFromCsv() {
    const uploads = [];
    try {
        const fileContent = await fs.readFile(resumeUploadCsvPath, 'utf8');
        return new Promise((resolve, reject) => {
            const stream = require('stream');
            const bufferStream = new stream.PassThrough();
            bufferStream.end(fileContent);

            bufferStream
                .pipe(csv())
                .on('data', (row) => {
                    uploads.push({
                        ID: row.ID,
                        Filename: row.Filename,
                        OriginalName: row['Original Name'],
                        UploadDate: row['Upload Date'],
                        UploadedBy: row['Uploaded By'],
                        FileType: row['File Type'],
                        Description: row.Description
                    });
                })
                .on('end', () => {
                    resolve(uploads);
                })
                .on('error', (error) => {
                    reject(error);
                });
        });
    } catch (error) {
        console.error('Error reading uploads CSV:', error);
        throw error;
    }
}

async function writeUploadsToCsv(uploads) {
    const csvWriter = createCsvWriter({
        path: resumeUploadCsvPath,
        header: [
            {id: 'ID', title: 'ID'},
            {id: 'Filename', title: 'Filename'},
            {id: 'OriginalName', title: 'Original Name'},
            {id: 'UploadDate', title: 'Upload Date'},
            {id: 'UploadedBy', title: 'Uploaded By'},
            {id: 'FileType', title: 'File Type'},
            {id: 'Description', title: 'Description'}
        ]
    });

    await csvWriter.writeRecords(uploads);
}

// Middleware
function checkAuth(req, res, next) {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    next();
}

function checkAdmin(req, res, next) {
    if (req.session.user && req.session.user.role === 'Admin') {
        next();
    } else {
        res.status(403).send('Access denied. Admin rights required.');
    }
}

function checkManagerOrAbove(req, res, next) {
    if (req.session.user && ['Admin', 'Manager'].includes(req.session.user.role)) {
        next();
    } else {
        res.status(403).send('Access denied. Manager rights or above required.');
    }
}

function checkSystemAdmin(req, res, next) {
    console.log('User session:', req.session.user);
    if (req.session.user && req.session.user.role === 'System Admin') {
        next();
    } else {
        res.status(403).send('Access denied. System Admin rights required.');
    }
}

// Routes
app.get('/login', (req, res) => {
    res.render('login', {
        error: null,
        email: '',
        showRegisterLink: false,
        showResetLink: false
    });
});

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        console.log('Login attempt for:', email);

        const users = await readUsersFromCsv();
        console.log('Users read from CSV:', users.length);

        const user = users.find(u => u.Email && u.Email.toLowerCase() === email.toLowerCase());
        console.log('User found:', user ? 'Yes' : 'No');
        if (user) {
            console.log('User details:', { ...user, Password: '[REDACTED]' });
        }

        if (!user) {
            console.log('User not found');
            return res.render('login', { 
                error: 'User not found. Would you like to register?', 
                email: email, 
                showRegisterLink: true, 
                showResetLink: false
            });
        }

        const passwordMatch = await bcrypt.compare(password, user.Password);
        console.log('Password match:', passwordMatch);

        if (passwordMatch) {
            req.session.user = {
                id: user.ID,
                email: user.Email,
                role: user.Role,
                firstName: user['First Name'],
                lastName: user['Last Name'],
                company: user.Company,
                managerId: user['Manager ID'],
                supervisorId: user['Supervisor ID']
            };
            req.session.loginAttempts = 0;
            console.log('Login successful, redirecting to dashboard');
            return res.redirect('/dashboard');
        } else {
            console.log('Invalid password');
            return res.render('login', {
                error: 'Incorrect password. Please try again or reset your password.',
                email: email,
                showRegisterLink: false,
                showResetLink: true
            });
        }
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).render('login', {
            error: 'An error occurred during login. Please try again later.',
            email: '',
            showRegisterLink: false,
            showResetLink: false
        });
    }
});

app.get('/register', (req, res) => {
    res.render('register', { error: null, email: req.query.email || '' });
});

app.post('/register', async (req, res) => {
    try {
        const { firstName, lastName, email, password, confirmPassword } = req.body;
        console.log('Registration attempt for:', email);

        if (password !== confirmPassword) {
            return res.render('register', { 
                error: 'Passwords do not match', 
                firstName, 
                lastName, 
                email 
            });
        }

        let users = await readUsersFromCsv();
        console.log('Current users count:', users.length);

        if (users.some(user => user.Email === email)) {
            return res.render('register', { 
                error: 'Email already registered', 
                firstName, 
                lastName, 
                email 
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = {
            ID: crypto.randomUUID(),
            'First Name': firstName,
            'Last Name': lastName,
            Email: email,
            Password: hashedPassword,
            Role: 'User',
            Company: 'IA',
            'Manager ID': '',
            'Supervisor ID': '',
            'Mobile Number': '',
            Street: '',
            City: '',
            State: '',
            'Zip Code': '',
            Country: '',
            isUSA: 'false'
        };

        users.push(newUser);
        await writeUsersToCsv(users);

        console.log('New user registered:', email);
        console.log('Updated users count:', users.length);

        res.redirect('/login');
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).render('register', { 
            error: 'An error occurred during registration', 
            firstName: req.body.firstName, 
            lastName: req.body.lastName, 
            email: req.body.email 
        });
    }
});

app.get('/dashboard', checkAuth, async (req, res) => {
    try {
        const uploads = await readUploadsFromCsv();
        res.render('dashboard', { user: req.session.user, files: uploads });
    } catch (error) {
        console.error('Error reading uploads:', error);
        res.status(500).send('Error reading uploads');
    }
});

app.post('/upload', checkAuth, upload.array('files'), async (req, res) => {
    try {
        const { fileType, fileDescription } = req.body;
        const uploads = await readUploadsFromCsv();

        for (const file of req.files) {
            const newUpload = {
                ID: crypto.randomUUID(),
                Filename: file.filename,
                'Original Name': file.originalname,
                'Upload Date': new Date().toLocaleString(),
                'Uploaded By': req.session.user.email,
                'File Type': fileType,
                Description: fileDescription
            };
            uploads.push(newUpload);
        }

        await writeUploadsToCsv(uploads);
        res.redirect('/dashboard');
    } catch (error) {
        console.error('Error during file upload:', error);
        res.status(500).send('An error occurred during file upload');
    }
});

app.get('/userprofileupdate/:id?', checkAuth, async (req, res) => {
    try {
        let user;
        if (req.params.id) {
            user = await User.findById(req.params.id);
            if (!user) {
                return res.status(404).send('User not found');
            }
        } else {
            user = req.session.user;
        }
        res.render('userprofileupdate', { user: user });
    } catch (error) {
        console.error('Error fetching user data:', error);
        res.status(500).send('Error fetching user data');
    }
});

app.post('/userprofileupdate/:id?', checkAuth, async (req, res) => {
    try {
        console.log('Session user:', req.session.user);
        console.log('Params id:', req.params.id);
        
        const userId = req.params.id || req.session.user.id;
        console.log('User ID to update:', userId);
        
        let user = await User.findById(userId);
        console.log('Found user:', user);

        if (!user) {
            console.log('User not found');
            return res.status(404).send('User not found');
        }

        // Update user fields
        const updatedUserData = {
            id: user.id,
            firstName: req.body.firstName || user.firstName,
            lastName: req.body.lastName || user.lastName,
            email: req.body.email || user.email,
            password: user.password, // Keep the existing password if not changed
            role: user.role,
            company: user.company,
            managerID: user.managerID,
            supervisorID: user.supervisorID,
            mobileNumber: req.body.mobileNumber || user.mobileNumber,
            address: {
                street: req.body.street || user.address.street,
                city: req.body.city || user.address.city,
                state: req.body.state || user.address.state,
                zipCode: req.body.zipCode || user.address.zipCode,
                country: req.body.country || user.address.country
            },
            isUSA: req.body.isUSA === 'true'
        };

        console.log('Updated user data:', updatedUserData);

        // Update password if provided
        if (req.body.password && req.body.password === req.body.confirmPassword) {
            updatedUserData.password = await bcrypt.hash(req.body.password, 10);
        }

        const updatedUser = await User.save(updatedUserData);
        console.log('User after save:', updatedUser);

        // Update session data if it's the logged-in user
        if (userId === req.session.user.id) {
            req.session.user = updatedUser;
            console.log('Updated session user:', req.session.user);
        }

        res.redirect('/user-list');
    } catch (error) {
        console.error('Error updating user profile:', error);
        res.status(500).send('Error updating user profile: ' + error.message);
    }
});

app.get('/user-list', checkAuth, async (req, res) => {
    try {
        console.log('Fetching user list');
        console.log('Current user:', req.session.user);
        
        const allUsers = await readUsersFromCsv();
        console.log('All users:', allUsers);
        
        let filteredUsers;

        switch (req.session.user.role) {
            case 'System Admin':
            case 'Admin':
                filteredUsers = allUsers;
                break;
            case 'Manager':
                filteredUsers = allUsers.filter(u => 
                    u.Company === req.session.user.company && 
                    (u['Manager ID'] === req.session.user.id || u.ID === req.session.user.id || u.Role === 'User' || u.Role === 'Supervisor')
                );
                break;
            case 'Supervisor':
                filteredUsers = allUsers.filter(u => 
                    u.Company === req.session.user.company && 
                    (u['Supervisor ID'] === req.session.user.id || u.ID === req.session.user.id || u.Role === 'User')
                );
                break;
            default: // Regular User
                filteredUsers = allUsers.filter(u => u.ID === req.session.user.id);
                break;
        }

        console.log('Filtered users:', filteredUsers);

        res.render('user-list', { 
            users: filteredUsers, 
            currentUser: req.session.user,
            getManagerName: (id) => {
                const manager = allUsers.find(u => u.ID === id);
                return manager ? `${manager['First Name']} ${manager['Last Name']}` : 'N/A';
            },
            getSupervisorName: (id) => {
                const supervisor = allUsers.find(u => u.ID === id);
                return supervisor ? `${supervisor['First Name']} ${supervisor['Last Name']}` : 'N/A';
            }
        });
    } catch (error) {
        console.error('Error fetching user list:', error);
        res.status(500).send('An error occurred while fetching the user list: ' + error.message);
    }
});

app.post('/change-role', checkAuth, checkSystemAdmin, async (req, res) => {
    try {
        const { userId, newRole } = req.body;

        if (!['User', 'Supervisor', 'Manager', 'Admin', 'System Admin'].includes(newRole)) {
            return res.status(400).json({ success: false, message: 'Invalid role.' });
        }

        // Check if the current user is trying to assign a role they don't have access to
        if (req.session.user.role !== 'System Admin' && newRole === 'System Admin') {
            return res.status(403).json({ success: false, message: 'Only System Admins can assign the System Admin role.' });
        }

        const users = await readUsersFromCsv();
        const userIndex = users.findIndex(u => u.ID === userId);

        if (userIndex === -1) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }

        users[userIndex].Role = newRole;
        await writeUsersToCsv(users);

        res.json({ success: true, message: 'Role updated successfully.' });
    } catch (error) {
        console.error('Error changing role:', error);
        res.status(500).json({ success: false, message: 'An error occurred while changing the role.' });
    }
});

app.get('/add-user', checkAuth, checkSystemAdmin, (req, res) => {
    console.log('User session:', req.session.user);
    res.render('add-user');
});

app.post('/add-user', checkAuth, checkSystemAdmin, async (req, res) => {
    try {
        const { email, password, firstName, lastName, mobileNumber, country, city, state, zipCode, role, company } = req.body;
        const users = await readUsersFromCsv();
        
        // Check if user already exists
        if (users.find(u => u.Email === email)) {
            return res.status(400).send('User with this email already exists');
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = {
            ID: crypto.randomUUID(),
            Email: email,
            Password: hashedPassword,
            'First Name': firstName,
            'Last Name': lastName,
            'Mobile Number': mobileNumber,
            Country: country,
            City: city,
            State: state,
            'Zip Code': zipCode,
            Role: role,
            Company: company,
            'Manager ID': null,
            'Supervisor ID': null,
            isUSA: 'false'
        };

        users.push(newUser);
        await writeUsersToCsv(users);

        res.redirect('/user-list');
    } catch (error) {
        console.error('Error adding new user:', error);
        res.status(500).send('An error occurred while adding the new user');
    }
});

app.post('/assign-supervisor', checkAuth, checkManagerOrAbove, async (req, res) => {
    try {
        const { userId, supervisorId } = req.body;
        const users = await readUsersFromCsv();
        const userIndex = users.findIndex(u => u.ID === userId);
        const supervisorIndex = users.findIndex(u => u.ID === supervisorId);
        
        if (userIndex !== -1 && supervisorIndex !== -1) {
            users[userIndex]['Supervisor ID'] = supervisorId;
            await writeUsersToCsv(users);
            res.json({ success: true });
        } else {
            res.status(404).json({ success: false, message: 'User or Supervisor not found' });
        }
    } catch (error) {
        console.error('Error assigning supervisor:', error);
        res.status(500).json({ success: false, message: 'An error occurred while assigning the supervisor' });
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Error destroying session:', err);
            return res.status(500).send('An error occurred during logout');
        }
        res.redirect('/login');
    });
});

app.get('/check-session', (req, res) => {
    res.json(req.session.user || { message: 'Not logged in' });
});

app.get('/debug-users', async (req, res) => {
    try {
        const users = await readUsersFromCsv();
        res.json(users);
    } catch (error) {
        res.status(500).json({ error: 'Error reading users' });
    }
});

app.get('/reset-password', (req, res) => {
    res.render('reset-password', { email: req.query.email || '' });
});

app.post('/reset-password', async (req, res) => {
    // Implement password reset logic here
});

app.get('/upload', (req, res) => {
    res.render('upload', { message: null });
});

app.post('/upload', upload.single('file'), (req, res) => {
    if (!req.file) {
        return res.render('upload', { message: 'No file uploaded. Please try again.' });
    }
    console.log('File uploaded:', req.file);
    res.render('upload', { message: 'File uploaded successfully!' });
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});

// Error handling
process.on('uncaughtException', (error) => {
    console.error('Uncaught Exception:', error);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});