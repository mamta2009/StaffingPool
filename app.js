const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const path = require('path');
const fs = require('fs');
const csv = require('csv-parser');
const createCsvWriter = require('csv-writer').createObjectCsvWriter;
const multer = require('multer');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const http = require('http');

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

// Ensure the views directory is correctly set up
app.set('views', path.join(__dirname, 'views'));

// Path to user profile CSV
const userProfileFilePath = '/Users/mamtasonwalkarm2/StaffingPool/userprofile.csv';
console.log('User profile file path:', userProfileFilePath);
const resumeUploadCsvPath = path.join(__dirname, 'resumeupload.csv');
const resumeContactsCsvPath = path.join(__dirname, 'Resumencontacts.csv');
const uploadsDir = path.join(__dirname, 'uploads');
const exportDir = path.join(__dirname, 'exports');

// Ensure the export directory exists
async function ensureExportDirExists() {
    try {
        await fs.access(exportDir);
    } catch (error) {
        if (error.code === 'ENOENT') {
            await fs.mkdir(exportDir, { recursive: true });
        } else {
            throw error;
        }
    }
}

// Ensure the uploads directory exists
async function ensureUploadsDirExists() {
    try {
        await fs.access(uploadsDir);
    } catch (error) {
        if (error.code === 'ENOENT') {
            await fs.mkdir(uploadsDir, { recursive: true });
        } else {
            throw error;
        }
    }
}

// Set up multer storage
const storage = multer.diskStorage({
    destination: async (req, file, cb) => {
        await ensureUploadsDirExists();
        cb(null, uploadsDir);
    },
    filename: (req, file, cb) => {
        const uniqueName = `${Date.now()}-${file.originalname}`;
        cb(null, uniqueName);
    }
});

const upload = multer({ storage: storage });

// Helper function to read users from CSV
function readUsersFromCsv() {
    return new Promise((resolve, reject) => {
        const users = [];
        fs.createReadStream(userProfileFilePath)
            .pipe(csv({
                mapHeaders: ({ header }) => {
                    switch (header) {
                        case 'ID': return 'id';
                        case 'First Name': return 'firstName';
                        case 'Last Name': return 'lastName';
                        case 'Email': return 'email';
                        case 'Password': return 'password';
                        case 'Role': return 'role';
                        case 'Company': return 'company';
                        case 'Manager ID': return 'managerId';
                        case 'Supervisor ID': return 'supervisorId';
                        default: return header;
                    }
                }
            }))
            .on('data', (row) => {
                if (row.email) {
                    users.push(row);
                } else {
                    console.warn('Skipping invalid user entry:', row);
                }
            })
            .on('end', () => {
                console.log('CSV file successfully processed');
                console.log('Valid users read from CSV:', users.length);
                resolve(users);
            })
            .on('error', (error) => {
                console.error('Error reading CSV:', error);
                reject(error);
            });
    });
}

// Helper function to write users to CSV
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
            {id: 'supervisorId', title: 'Supervisor ID'}
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

// Helper function to read uploads from CSV
function readUploadsFromCsv() {
    return new Promise((resolve, reject) => {
        const uploads = [];
        fs.createReadStream(resumeUploadCsvPath)
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
}

// Helper function to write uploads to CSV
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

// Function to clear resume upload CSV
function clearResumeUploadCsv() {
    const header = 'ID,Filename,Original Name,Upload Date,Uploaded By,File Type,Description\n';
    fs.writeFileSync(resumeUploadCsvPath, header, 'utf8');
    console.log('resumeupload.csv has been cleared and reset with header.');

    // Clear uploads directory
    fs.readdirSync(uploadsDir).forEach((file) => {
        const filePath = path.join(uploadsDir, file);
        fs.unlinkSync(filePath);
    });
    console.log('uploads directory has been cleared.');
}

// POST route for adding description
app.post('/adddescription', async (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }

    const { fileName, fileDescription } = req.body;
    const uploads = await readUploadsFromCsv();
    const file = uploads.find(file => file.Filename === fileName);

    if (file) {
        file.Description = fileDescription;
        await writeUploadsToCsv(uploads);
    }

    res.redirect('/dashboard');
});

// GET route for login
app.get('/login', (req, res) => {
    res.render('login', {
        error: null,
        email: '',
        showRegisterLink: false,
        showResetLink: false
    });
});

// POST route for login
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        console.log('Login attempt for:', email);

        const users = await readUsersFromCsv();
        console.log('Users read from CSV:', users.length);

        const user = users.find(u => u.email && u.email.toLowerCase() === email.toLowerCase());
        console.log('User found:', user ? 'Yes' : 'No');
        if (user) {
            console.log('User details:', { ...user, password: '[REDACTED]' });
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

        const passwordMatch = await bcrypt.compare(password, user.password);
        console.log('Password match:', passwordMatch);

        if (passwordMatch) {
            req.session.user = {
                id: user.id,
                email: user.email,
                role: user.role,
                firstName: user.firstName,
                lastName: user.lastName,
                company: user.company,
                managerId: user.managerId,
                supervisorId: user.supervisorId
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

// GET route for registration
app.get('/register', (req, res) => {
    res.render('register', { error: null, email: req.query.email || '' });
});

// POST route for registration
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

        let users = [];
        try {
            users = await readUsersFromCsv();
        } catch (error) {
            console.error('Error reading users CSV:', error);
            // If the file doesn't exist or is empty, we'll start with an empty array
        }

        console.log('Current users count:', users.length);

        if (users.some(user => user.email === email)) {
            return res.render('register', { 
                error: 'Email already registered', 
                firstName, 
                lastName, 
                email 
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = {
            id: crypto.randomUUID(),
            firstName,
            lastName,
            email,
            password: hashedPassword,
            role: 'User',
            company: 'IA',
            managerId: '',
            supervisorId: ''
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

// Middleware to check if user is logged in
function checkAuth(req, res, next) {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    next();
}

// Middleware to check roles
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

// Dashboard route
app.get('/dashboard', checkAuth, async (req, res) => {
    try {
        const uploads = await readUploadsFromCsv();
        res.render('dashboard', { user: req.session.user, files: uploads });
    } catch (error) {
        console.error('Error reading uploads:', error);
        res.status(500).send('Error reading uploads');
    }
});

// POST route for file upload
app.post('/upload', checkAuth, upload.array('files'), async (req, res) => {
    try {
        const { fileType, fileDescription } = req.body;
        const uploads = await readUploadsFromCsv();

        for (const file of req.files) {
            const newUpload = {
                ID: crypto.randomUUID(),
                Filename: file.filename,
                OriginalName: file.originalname,
                UploadDate: new Date().toLocaleString(),
                UploadedBy: req.session.user.email,
                FileType: fileType,
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

// GET route for user profile update
app.get('/userprofileupdate/:id?', checkAuth, async (req, res) => {
    try {
        let user;
        if (req.params.id) {
            // If an ID is provided, fetch that specific user
            user = await User.findById(req.params.id);
            if (!user) {
                return res.status(404).send('User not found');
            }
        } else {
            // If no ID is provided, use the logged-in user's data
            user = req.session.user;
        }
        res.render('userprofileupdate', { user: user });
    } catch (error) {
        console.error('Error fetching user data:', error);
        res.status(500).send('Error fetching user data');
    }
});

// POST route for user profile update
app.post('/userprofileupdate/:id?', checkAuth, async (req, res) => {
    try {
        let user;
        if (req.params.id) {
            // If an ID is provided, update that specific user
            user = await User.findById(req.params.id);
            if (!user) {
                return res.status(404).send('User not found');
            }
        } else {
            // If no ID is provided, update the logged-in user's data
            user = await User.findById(req.session.user._id);
        }

        // Update user fields
        user.firstName = req.body.firstName;
        user.lastName = req.body.lastName;
        user.email = req.body.email;
        // ... update other fields as necessary ...

        await user.save();

        // Update session data if it's the logged-in user
        if (!req.params.id || req.params.id === req.session.user._id.toString()) {
            req.session.user = user;
        }

        res.redirect('/dashboard');
    } catch (error) {
        console.error('Error updating user profile:', error);
        res.status(500).send('Error updating user profile');
    }
});

// Start the server
const port = process.env.PORT || 3000;
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});

// POST route for registration
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

        let users = [];
        try {
            users = await readUsersFromCsv();
        } catch (error) {
            console.error('Error reading users CSV:', error);
            // If the file doesn't exist or is empty, we'll start with an empty array
        }

        console.log('Current users count:', users.length);

        if (users.some(user => user.email === email)) {
            return res.render('register', { 
                error: 'Email already registered', 
                firstName, 
                lastName, 
                email 
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = {
            id: crypto.randomUUID(),
            firstName,
            lastName,
            email,
            password: hashedPassword,
            role: 'User',
            company: 'IA',
            managerId: '',
            supervisorId: ''
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

// Middleware to check if user is logged in
function checkAuth(req, res, next) {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    next();
}

// Middleware to check roles
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

// Dashboard route
app.get('/dashboard', checkAuth, async (req, res) => {
    try {
        const uploads = await readUploadsFromCsv();
        res.render('dashboard', { user: req.session.user, files: uploads });
    } catch (error) {
        console.error('Error reading uploads:', error);
        res.status(500).send('Error reading uploads');
    }
});

// POST route for file upload
app.post('/upload', checkAuth, upload.array('files'), async (req, res) => {
    try {
        const { fileType, fileDescription } = req.body;
        const uploads = await readUploadsFromCsv();

        for (const file of req.files) {
            const newUpload = {
                ID: crypto.randomUUID(),
                Filename: file.filename,
                OriginalName: file.originalname,
                UploadDate: new Date().toLocaleString(),
                UploadedBy: req.session.user.email,
                FileType: fileType,
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

// GET route for user profile update
app.get('/userprofileupdate', checkAuth, (req, res) => {
    res.render('userprofileupdate', { user: req.session.user });
});

// POST route for user profile update
app.post('/userprofileupdate', checkAuth, async (req, res) => {
    const { firstName, lastName, mobileNumber, country, city, state, zipCode } = req.body;
    try {
        const users = await readUsersFromCsv();
        const userIndex = users.findIndex(u => u.email === req.session.user.email);

        if (userIndex !== -1) {
            users[userIndex] = {
                ...users[userIndex],
                firstName,
                lastName,
                mobileNumber,
                country,
                city,
                state,
                zipCode
            };

            await writeUsersToCsv(users);
            req.session.user = users[userIndex];
            res.redirect('/dashboard');
        } else {
            res.status(404).send('User not found');
        }
    } catch (error) {
        console.error('Error updating user profile:', error);
        res.status(500).send('An error occurred while updating the profile');
    }
});

// POST route for deleting a file
app.post('/deletefile', (req, res) => {
    const { fileName } = req.body;
    if (!fileName) {
        return res.status(400).send('Filename is missing from the request body');
    }

    const filePath = path.join(uploadsDir, fileName);
    fs.unlink(filePath, (err) => {
        if (err) {
            console.error('Error deleting file:', err);
            return res.status(500).send('An error occurred while deleting the file');
        }

        // Remove the file entry from the CSV
        readUploadsFromCsv()
            .then((uploads) => {
                const updatedUploads = uploads.filter(upload => upload.Filename !== fileName);
                return writeUploadsToCsv(updatedUploads);
            })
            .then(() => {
                res.redirect('/dashboard');
            })
            .catch((error) => {
                console.error('Error updating CSV:', error);
                res.status(500).send('An error occurred while updating the CSV');
            });
    });
});

// GET route for clearing uploads
app.get('/clear-uploads', checkAuth, (req, res) => {
    try {
        clearResumeUploadCsv();
        res.send('All uploads have been cleared successfully.');
    } catch (error) {
        console.error('Error clearing uploads:', error);
        res.status(500).send('An error occurred while clearing uploads.');
    }
});

// GET route for clearing users
app.get('/clear-users', checkAuth, (req, res) => {
    try {
        clearUserProfileCsv();
        req.session.destroy(); // Destroy the current session
        res.send('All user information has been cleared successfully. You will be logged out.');
    } catch (error) {
        console.error('Error clearing user information:', error);
        res.status(500).send('An error occurred while clearing user information.');
    }
});

function clearUserProfileCsv() {
    const header = 'Email,Password,FirstName,LastName,MobileNumber,Country,City,State,ZipCode,RegistrationDate,Role,Archived,ResetToken,ResetTokenExpires,Company,ManagerId,SupervisorId\n';
    fs.writeFileSync(userProfileFilePath, header, 'utf8');
    console.log('userprofile.csv has been cleared and reset with header.');
}

// Helper function to group users by company
function groupUsersByCompany(users) {
    return users.reduce((acc, user) => {
        const company = user.company || 'IA';
        if (!acc[company]) {
            acc[company] = [];
        }
        acc[company].push(user);
        return acc;
    }, {});
}

// User List route
app.get('/user-list', checkAuth, async (req, res) => {
    try {
        const allUsers = await readUsersFromCsv();
        let filteredUsers;

        switch (req.session.user.role) {
            case 'System Admin':
            case 'Admin':
                filteredUsers = allUsers;
                break;
            case 'Manager':
                filteredUsers = allUsers.filter(u => 
                    u.company === req.session.user.company && 
                    (u.managerId === req.session.user.id || u.id === req.session.user.id || u.role === 'User' || u.role === 'Supervisor')
                );
                break;
            case 'Supervisor':
                filteredUsers = allUsers.filter(u => 
                    u.company === req.session.user.company && 
                    (u.supervisorId === req.session.user.id || u.id === req.session.user.id || u.role === 'User')
                );
                break;
            default: // Regular User
                filteredUsers = allUsers.filter(u => u.id === req.session.user.id);
                break;
        }

        res.render('user-list', { 
            users: filteredUsers, 
            currentUser: req.session.user,
            getManagerName: (id) => {
                const manager = allUsers.find(u => u.id === id);
                return manager ? `${manager.firstName} ${manager.lastName}` : 'N/A';
            },
            getSupervisorName: (id) => {
                const supervisor = allUsers.find(u => u.id === id);
                return supervisor ? `${supervisor.firstName} ${supervisor.lastName}` : 'N/A';
            },
            groupUsersByCompany
        });
    } catch (error) {
        console.error('Error fetching user list:', error);
        res.status(500).send('An error occurred while fetching the user list');
    }
});

// Add Company route (System Admin and Admin only)
app.post('/add-company', checkAuth, checkSystemAdmin, async (req, res) => {
    try {
        const { companyName } = req.body;
        // Implement logic to add company
        // This might involve updating a separate companies list or adding to user records
        res.json({ success: true, message: 'Company added successfully' });
    } catch (error) {
        console.error('Error adding company:', error);
        res.status(500).json({ success: false, message: 'An error occurred while adding the company' });
    }
});

// Assign Manager route (System Admin and Admin only)
app.post('/assign-manager', checkAuth, checkSystemAdmin, async (req, res) => {
    try {
        const { userId, managerId } = req.body;
        const users = await readUsersFromCsv();
        const userIndex = users.findIndex(u => u.id === userId);
        const managerIndex = users.findIndex(u => u.id === managerId);

        if (userIndex !== -1 && managerIndex !== -1) {
            users[userIndex].managerId = managerId;
            users[userIndex].company = users[managerIndex].company;
            await writeUsersToCsv(users);
            res.json({ success: true, message: 'Manager assigned successfully' });
        } else {
            res.status(404).json({ success: false, message: 'User or manager not found' });
        }
    } catch (error) {
        console.error('Error assigning manager:', error);
        res.status(500).json({ success: false, message: 'An error occurred while assigning the manager' });
    }
});

// Change role route
app.post('/change-role', checkAuth, async (req, res) => {
    try {
        const { userId, newRole } = req.body;
        
        // Check if the current user has permission to change roles
        if (req.session.user.role !== 'System Admin' && req.session.user.role !== 'Admin') {
            return res.status(403).json({ success: false, message: 'You do not have permission to change roles.' });
        }

        // Check if the current user is trying to assign a role they don't have access to
        if (req.session.user.role !== 'System Admin' && newRole === 'System Admin') {
            return res.status(403).json({ success: false, message: 'Only System Admins can assign the System Admin role.' });
        }

        const users = await readUsersFromCsv();
        const userIndex = users.findIndex(u => u.id === userId);

        if (userIndex === -1) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }

        users[userIndex].role = newRole;
        await writeUsersToCsv(users);

        res.json({ success: true, message: 'Role updated successfully.' });
    } catch (error) {
        console.error('Error changing role:', error);
        res.status(500).json({ success: false, message: 'An error occurred while changing the role.' });
    }
});

// Add User route (only accessible by System Admin and Admin)
app.get('/add-user', checkAuth, checkSystemAdmin, (req, res) => {
    console.log('User session:', req.session.user);
    res.render('add-user');
});

app.post('/add-user', checkAuth, checkSystemAdmin, async (req, res) => {
    try {
        const { email, password, firstName, lastName, mobileNumber, country, city, state, zipCode, role, company } = req.body;
        const users = await readUsersFromCsv();
        
        // Check if user already exists
        if (users.find(u => u.email === email)) {
            return res.status(400).send('User with this email already exists');
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = {
            email,
            password: hashedPassword,
            firstName,
            lastName,
            mobileNumber,
            country,
            city,
            state,
            zipCode,
            registrationDate: new Date().toISOString(),
            role,
            company,
            managerId: null,
            supervisorId: null,
            archived: 'false'
        };

        users.push(newUser);
        await writeUsersToCsv(users);

        res.redirect('/user-list');
    } catch (error) {
        console.error('Error adding new user:', error);
        res.status(500).send('An error occurred while adding the new user');
    }
});

// Assign Supervisor route (Manager only)
app.post('/assign-supervisor', checkAuth, checkManagerOrAbove, async (req, res) => {
    try {
        const { userId, supervisorId } = req.body;
        const users = await readUsersFromCsv();
        const userIndex = users.findIndex(u => u.id === userId);
        const supervisorIndex = users.findIndex(u => u.id === supervisorId);
        
        if (userIndex !== -1 && supervisorIndex !== -1) {
            users[userIndex].supervisorId = supervisorId;
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

// Logout route
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Error destroying session:', err);
            return res.status(500).send('An error occurred during logout');
        }
        res.redirect('/login');
    });
});

// Start the server
const server = http.createServer(app);

server.on('error', (error) => {
    console.error('Server error:', error);
});

process.on('uncaughtException', (error) => {
    console.error('Uncaught Exception:', error);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});


app.get('/check-session', (req, res) => {
    res.json(req.session.user || { message: 'Not logged in' });
});

fs.access(userProfileFilePath, fs.constants.F_OK | fs.constants.R_OK, (err) => {
    if (err) {
        console.error(`${userProfileFilePath} ${err.code === 'ENOENT' ? 'does not exist' : 'is not readable'}`);
    } else {
        console.log(`${userProfileFilePath} exists and is readable`);
    }
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

// Route to render the upload form
app.get('/upload', (req, res) => {
    res.render('upload', { message: null });
});

// Route to handle file upload
app.post('/upload', upload.single('file'), (req, res) => {
    if (!req.file) {
        return res.render('upload', { message: 'No file uploaded. Please try again.' });
    }
    console.log('File uploaded:', req.file);
    res.render('upload', { message: 'File uploaded successfully!' });
});
