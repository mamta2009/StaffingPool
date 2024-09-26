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
const archiver = require('archiver');

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
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        cb(null, file.originalname); // Keep the original filename
    }
});

const upload = multer({ storage: storage });

// Helper functions
async function readUsersFromCsv() {
    try {
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
    } catch (error) {
        console.error('Error reading users from CSV:', error);
        throw error;
    }
}


async function writeUsersToCsv(users) {
    try {
        const csvWriter = createCsvWriter({
            path: userProfileFilePath,
            header: [
                {id: 'ID', title: 'ID'},
                {id: 'First Name', title: 'First Name'},
                {id: 'Last Name', title: 'Last Name'},
                {id: 'Email', title: 'Email'},
                {id: 'Password', title: 'Password'},
                {id: 'Role', title: 'Role'},
                {id: 'Company', title: 'Company'},
                {id: 'Manager ID', title: 'Manager ID'},
                {id: 'Supervisor ID', title: 'Supervisor ID'},
                {id: 'Mobile Number', title: 'Mobile Number'},
                {id: 'Street', title: 'Street'},
                {id: 'City', title: 'City'},
                {id: 'State', title: 'State'},
                {id: 'Zip Code', title: 'Zip Code'},
                {id: 'Country', title: 'Country'},
                {id: 'isUSA', title: 'isUSA'}
            ]
        });

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
                        'Original Name': row['Original Name'],
                        'Upload Date': row['Upload Date'],
                        'Uploaded By': row['Uploaded By'],
                        'File Type': row['File Type'],
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

const roles = {
    ADMIN: 'admin',
    USER: 'user'
};

function checkRole(role) {
    return (req, res, next) => {
        if (req.session.user && req.session.user.role === role) {
            next();
        } else {
            res.status(403).send('Access denied');
        }
    };
}

// Middleware
function checkAuth(req, res, next) {
    if (req.session.user) {
        next();
    } else {
        res.redirect('/login');
    }
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
// ... (previous code remains the same)


app.post('/exportfiles', async (req, res) => {
    console.log('Entering /exportfiles route');
    console.log('Request body:', req.body);

    try {
        let selectedFiles = req.body.selectedFiles;
        console.log('Selected files:', selectedFiles);
        
        // Ensure selectedFiles is always an array
        if (!Array.isArray(selectedFiles)) {
            selectedFiles = [selectedFiles];
        }
        
        if (!selectedFiles || selectedFiles.length === 0) {
            console.log('No files selected for export');
            return res.status(400).send('No files selected for export');
        }

        // Create a temporary directory for exported files
        const exportDir = path.join(__dirname, 'exported_files');
        console.log('Export directory:', exportDir);
        await fs.mkdir(exportDir, { recursive: true });

        // Copy selected files to the export directory
        for (const filename of selectedFiles) {
            const sourcePath = path.join(__dirname, 'uploads', filename);
            const destPath = path.join(exportDir, filename);
            console.log(`Copying file from ${sourcePath} to ${destPath}`);
            
            try {
                await fs.access(sourcePath);
                await fs.copyFile(sourcePath, destPath);
            } catch (err) {
                console.error(`Error copying file ${filename}:`, err);
                // Skip this file and continue with others
                continue;
            }
        }

        // Create a zip file of the exported files
        const zipFilename = `exported_files_${Date.now()}.zip`;
        const zipFilePath = path.join(__dirname, zipFilename);
        console.log('Zip file path:', zipFilePath);
        const output = require('fs').createWriteStream(zipFilePath);
        const archive = archiver('zip', { zlib: { level: 9 } });

        output.on('close', () => {
            console.log('Zip file created successfully');
            // Send the zip file to the client
            res.download(zipFilePath, zipFilename, async (err) => {
                if (err) {
                    console.error('Error sending zip file:', err);
                }
                console.log('Cleaning up temporary files');
                // Clean up: delete the zip file and exported files
                try {
                    await fs.unlink(zipFilePath);
                    await fs.rm(exportDir, { recursive: true, force: true });
                } catch (cleanupErr) {
                    console.error('Error during cleanup:', cleanupErr);
                }
            });
        });

        archive.on('error', (err) => {
            console.error('Error creating zip file:', err);
            throw err;
        });

        archive.pipe(output);
        archive.directory(exportDir, false);
        archive.finalize();

    } catch (error) {
        console.error('Error exporting files:', error);
        res.status(500).send('An error occurred while exporting files');
    }
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

        if (!firstName || !lastName || !email || !password || !confirmPassword) {
            console.log('Missing required fields');
            return res.render('register', { 
                error: 'All fields are required', 
                firstName, 
                lastName, 
                email 
            });
        }

        if (password !== confirmPassword) {
            console.log('Passwords do not match');
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
            console.log('Email already registered:', email);
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
        console.log('Uploads:', uploads); // Log the uploads array
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
            console.log('Uploaded file:', file.originalname); // Log the file name
            const newUpload = {
                ID: crypto.randomUUID(),
                Filename: file.originalname, // Use the original filename
                'Original Name': file.originalname,
                'Upload Date': new Date().toLocaleString(),
                'Uploaded By': req.session.user.email,
                'File Type': fileType,
                Description: fileDescription
            };
            uploads.push(newUpload);
            console.log('Uploaded file:', newUpload);
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

        res.redirect('/userlist');
    } catch (error) {
        console.error('Error updating user profile:', error);
        res.status(500).send('Error updating user profile: ' + error.message);
    }
});

app.get('/userlist', checkAuth, async (req, res) => {
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

        res.render('userlist', { 
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

app.post('/change-role', checkAuth, checkAdmin, async (req, res) => {
    try {
        const { userId, newRole } = req.body;
        const currentUser = req.session.user;

        if (!['User', 'Supervisor', 'Manager', 'Admin', 'System Admin'].includes(newRole)) {
            return res.status(400).json({ success: false, message: 'Invalid role.' });
        }

        // Prevent changing own role
        if (userId === currentUser.id) {
            return res.status(403).json({ success: false, message: 'You cannot change your own role.' });
        }

        // Check if the current user is trying to assign a role they don't have access to
        if (currentUser.role !== 'System Admin' && newRole === 'System Admin') {
            return res.status(403).json({ success: false, message: 'Only System Admins can assign the System Admin role.' });
        }

        const users = await readUsersFromCsv();
        const userIndex = users.findIndex(u => u.ID === userId);

        if (userIndex === -1) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }

        // Prevent removing the last admin
        if (users[userIndex].Role === 'Admin' && newRole !== 'Admin') {
            const adminCount = users.filter(u => u.Role === 'Admin').length;
            if (adminCount <= 1) {
                return res.status(403).json({ success: false, message: 'Cannot remove the last admin.' });
            }
        }

        users[userIndex].Role = newRole;
        await writeUsersToCsv(users);

        res.redirect('/userlist');
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

        res.redirect('/userlist');
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

app.post('/deletefile', checkAuth, checkRole(roles.ADMIN), async (req, res) => {
    console.log('Received request to delete file');
    console.log('Request body:', req.body);
    const { fileName } = req.body;

    if (!fileName) {
        console.log('Filename is missing in the request body');
        return res.status(400).send('Filename is required');
    }

    console.log('Filename received:', fileName);

    try {
        // Read the CSV file to find the file entry
        const uploads = await readUploadsFromCsv();
        const fileIndex = uploads.findIndex(file => file.Filename === fileName);

        if (fileIndex === -1) {
            console.log('File not found in CSV:', fileName);
            return res.status(404).send('File not found');
        }

        // Remove the file entry from the CSV data
        const [fileToDelete] = uploads.splice(fileIndex, 1);

        // Write the updated data back to the CSV file
        await writeUploadsToCsv(uploads);

        // Delete the file from the file system
        const filePath = path.join(uploadsDir, fileName);
        await fs.unlink(filePath);

        console.log('File deleted successfully:', filePath);
        res.redirect('/dashboard'); // Redirect to the dashboard
    } catch (error) {
        console.error('Error deleting file:', error);
        res.status(500).send('Error deleting file');
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

app.get('/upload', (req, res) => {
    res.render('upload', { message: null });
});

app.post('/upload', upload.single('file'), (req, res) => {
    if (!req.file) {
        return res.render('upload', { message: 'No file uploaded. Please try again.' });
    }
    console.log('File uploaded:', req.file.originalname); // Log the file name
    res.render('upload', { message: 'File uploaded successfully!' });
});

// Route accessible only by admin
app.get('/admin', checkAuth, checkRole(roles.ADMIN), (req, res) => {
    res.send('Welcome Admin');
});

// Route accessible only by regular users
app.get('/user', checkAuth, checkRole(roles.USER), (req, res) => {
    res.send('Welcome User');
});

// Route accessible by both admin and regular users
app.get('/dashboard', checkAuth, (req, res) => {
    res.render('dashboard', { user: req.session.user, files: uploads });
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