const fs = require('fs');
const path = require('path');
const csv = require('csv-parser');
const createCsvWriter = require('csv-writer').createObjectCsvWriter;

const CSV_FILE_PATH = path.join(__dirname, '..', 'data', 'userprofile.csv');

class User {
  constructor(data) {
    this.id = data.ID || data.id;
    this.firstName = data['First Name'] || data.firstName;
    this.lastName = data['Last Name'] || data.lastName;
    this.email = data.Email || data.email;
    this.password = data.Password || data.password;
    this.role = data.Role || data.role;
    this.company = data.Company || data.company;
    this.managerID = data['Manager ID'] || data.managerID;
    this.supervisorID = data['Supervisor ID'] || data.supervisorID;
    this.mobileNumber = data['Mobile Number'] || data.mobileNumber || '';
    this.address = {
      street: data.Street || data.address?.street || '',
      city: data.City || data.address?.city || '',
      state: data.State || data.address?.state || '',
      zipCode: data['Zip Code'] || data.address?.zipCode || '',
      country: data.Country || data.address?.country || ''
    };
    this.isUSA = data.isUSA === 'true' || data.isUSA === true;
  }

  static async findById(id) {
    console.log('Searching for user with id:', id);
    const users = await this.getAllUsers();
    const user = users.find(user => user.id === id);
    console.log('Found user:', user);
    return user;
  }

  static async findByEmail(email) {
    const users = await this.getAllUsers();
    return users.find(user => user.email === email);
  }

  static async getAllUsers() {
    return new Promise((resolve, reject) => {
      const users = [];
      fs.createReadStream(CSV_FILE_PATH)
        .pipe(csv())
        .on('data', (data) => users.push(new User(data)))
        .on('end', () => {
          console.log('All users:', users);
          resolve(users);
        })
        .on('error', (error) => reject(error));
    });
  }

  static async save(userData) {
    console.log('Saving user data:', userData);
    const users = await this.getAllUsers();
    const existingUserIndex = users.findIndex(user => user.id === userData.id);

    if (existingUserIndex !== -1) {
      // Update existing user
      users[existingUserIndex] = new User(userData);
    } else {
      // Add new user
      userData.id = userData.id || Date.now().toString();
      users.push(new User(userData));
    }

    const csvWriter = createCsvWriter({
      path: CSV_FILE_PATH,
      header: [
        {id: 'id', title: 'ID'},
        {id: 'firstName', title: 'First Name'},
        {id: 'lastName', title: 'Last Name'},
        {id: 'email', title: 'Email'},
        {id: 'password', title: 'Password'},
        {id: 'role', title: 'Role'},
        {id: 'company', title: 'Company'},
        {id: 'managerID', title: 'Manager ID'},
        {id: 'supervisorID', title: 'Supervisor ID'},
        {id: 'mobileNumber', title: 'Mobile Number'},
        {id: 'street', title: 'Street'},
        {id: 'city', title: 'City'},
        {id: 'state', title: 'State'},
        {id: 'zipCode', title: 'Zip Code'},
        {id: 'country', title: 'Country'},
        {id: 'isUSA', title: 'isUSA'}
      ]
    });

    await csvWriter.writeRecords(users.map(user => ({
      id: user.id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      password: user.password,
      role: user.role,
      company: user.company,
      managerID: user.managerID,
      supervisorID: user.supervisorID,
      mobileNumber: user.mobileNumber,
      street: user.address.street,
      city: user.address.city,
      state: user.address.state,
      zipCode: user.address.zipCode,
      country: user.address.country,
      isUSA: user.isUSA
    })));

    console.log('User saved:', new User(userData));
    return new User(userData);
  }
}

module.exports = User;
