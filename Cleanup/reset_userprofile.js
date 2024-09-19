const fs = require('fs').promises;
const path = require('path');

const userProfileCsvPath = path.join(__dirname, 'userprofile.csv');
const backupPath = path.join(__dirname, 'userprofile_backup.csv');

// CSV header
const header = 'Email,Password,RegistrationDate,Role,Archived\n';

async function resetUserProfile() {
  try {
    // Check if the file exists
    try {
      await fs.access(userProfileCsvPath);
      console.log('Existing userprofile.csv found.');
      
      // Create a backup of the existing file
      await fs.copyFile(userProfileCsvPath, backupPath);
      console.log('Backup created: userprofile_backup.csv');
    } catch (error) {
      if (error.code === 'ENOENT') {
        console.log('No existing userprofile.csv found. A new file will be created.');
      } else {
        throw error;
      }
    }

    // Write the header to the file, overwriting any existing content
    await fs.writeFile(userProfileCsvPath, header);
    console.log('userprofile.csv has been reset with header only.');

    // Verify the file contents
    const fileContent = await fs.readFile(userProfileCsvPath, 'utf8');
    if (fileContent.trim() === header.trim()) {
      console.log('File contents verified. Reset successful.');
    } else {
      throw new Error('File contents do not match the expected header.');
    }

  } catch (error) {
    console.error('Error during reset process:', error.message);
    process.exit(1);
  }
}

resetUserProfile();
