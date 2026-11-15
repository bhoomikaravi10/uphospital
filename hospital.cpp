// Hospital Management System - C++ SQLite POC
// Build: g++ -std=c++17 hospital.cpp -lsqlite3 -lcrypto -o hospital
// Run:   ./hospital
//
// First run creates the database and asks you to create the administrator account.
// Passwords are stored as PBKDF2-HMAC-SHA256 hashes with random salts.

#include <iostream>
#include <string>
#include <limits>
#include <iomanip>
#include <sstream>
#include <vector>
#include <sqlite3.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

using namespace std;

sqlite3* db = nullptr;

string input(const string& prompt) {
    cout << prompt;
    string value;
    getline(cin, value);
    return value;
}

int numberInput(const string& prompt) {
    while (true) {
        string s = input(prompt);
        try {
            size_t pos = 0;
            int n = stoi(s, &pos);
            if (pos == s.size()) return n;
        } catch (...) {}
        cout << "Please enter a valid number.\n";
    }
}

string toHex(const unsigned char* data, int len) {
    stringstream ss;
    ss << hex << setfill('0');
    for (int i = 0; i < len; ++i) ss << setw(2) << (int)data[i];
    return ss.str();
}

bool fromHex(const string& hexText, unsigned char* out, int expectedBytes) {
    if ((int)hexText.size() != expectedBytes * 2) return false;
    for (int i = 0; i < expectedBytes; ++i) {
        try {
            out[i] = (unsigned char)stoi(hexText.substr(i * 2, 2), nullptr, 16);
        } catch (...) { return false; }
    }
    return true;
}

bool makePasswordHash(const string& password, string& saltHex, string& hashHex) {
    unsigned char salt[16], hash[32];
    if (RAND_bytes(salt, sizeof(salt)) != 1) return false;
    if (PKCS5_PBKDF2_HMAC(password.c_str(), (int)password.size(),
                          salt, sizeof(salt), 200000, EVP_sha256(),
                          sizeof(hash), hash) != 1) return false;
    saltHex = toHex(salt, sizeof(salt));
    hashHex = toHex(hash, sizeof(hash));
    return true;
}

bool verifyPassword(const string& password, const string& saltHex,
                    const string& expectedHashHex) {
    unsigned char salt[16], expected[32], actual[32];
    if (!fromHex(saltHex, salt, sizeof(salt)) ||
        !fromHex(expectedHashHex, expected, sizeof(expected))) return false;
    if (PKCS5_PBKDF2_HMAC(password.c_str(), (int)password.size(),
                          salt, sizeof(salt), 200000, EVP_sha256(),
                          sizeof(actual), actual) != 1) return false;
    // Constant-time comparison.
    unsigned char diff = 0;
    for (int i = 0; i < 32; ++i) diff |= actual[i] ^ expected[i];
    return diff == 0;
}

bool execute(const string& sql) {
    char* err = nullptr;
    if (sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &err) != SQLITE_OK) {
        cerr << "Database error: " << (err ? err : "unknown") << "\n";
        sqlite3_free(err);
        return false;
    }
    return true;
}

bool initializeDatabase() {
    const char* schema = R"SQL(
        PRAGMA foreign_keys = ON;

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            salt TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin','receptionist','approver'))
        );

        CREATE TABLE IF NOT EXISTS patients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            age INTEGER NOT NULL,
            gender TEXT NOT NULL,
            phone TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS doctors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            specialization TEXT NOT NULL,
            phone TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS appointments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER NOT NULL,
            doctor_id INTEGER NOT NULL,
            appointment_date TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Pending'
                CHECK(status IN ('Pending','Approved','Rejected')),
            FOREIGN KEY(patient_id) REFERENCES patients(id),
            FOREIGN KEY(doctor_id) REFERENCES doctors(id)
        );
    )SQL";
    return execute(schema);
}

int scalarCount(const string& sql) {
    sqlite3_stmt* stmt = nullptr;
    int count = 0;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK &&
        sqlite3_step(stmt) == SQLITE_ROW) count = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return count;
}

void createFirstAdmin() {
    if (scalarCount("SELECT COUNT(*) FROM users") != 0) return;

    cout << "\n=== First-time administrator setup ===\n";
    string username = input("Create admin username: ");
    string password = input("Create admin password: ");
    if (username.empty() || password.size() < 8) {
        cout << "Username cannot be empty and password must have at least 8 characters.\n";
        createFirstAdmin();
        return;
    }

    string salt, hash;
    if (!makePasswordHash(password, salt, hash)) {
        cout << "Could not create password hash.\n";
        return;
    }

    sqlite3_stmt* stmt = nullptr;
    const char* sql = "INSERT INTO users(username,salt,password_hash,role) VALUES(?,?,?,'admin')";
    sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, salt.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, hash.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt) == SQLITE_DONE) cout << "Administrator account created.\n";
    else cout << "Could not create account. Username may already exist.\n";
    sqlite3_finalize(stmt);
}

struct User {
    int id;
    string username;
    string role;
};

bool login(User& loggedIn) {
    cout << "\n========== HOSPITAL MANAGEMENT SYSTEM ==========\n";
    string username = input("Username: ");
    string password = input("Password: ");

    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT id, username, salt, password_hash, role FROM users WHERE username=?";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);

    bool success = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        string salt = (const char*)sqlite3_column_text(stmt, 2);
        string hash = (const char*)sqlite3_column_text(stmt, 3);
        if (verifyPassword(password, salt, hash)) {
            loggedIn.id = sqlite3_column_int(stmt, 0);
            loggedIn.username = (const char*)sqlite3_column_text(stmt, 1);
            loggedIn.role = (const char*)sqlite3_column_text(stmt, 4);
            success = true;
        }
    }
    sqlite3_finalize(stmt);
    if (!success) cout << "Invalid username or password.\n";
    return success;
}

bool addUser() {
    string username = input("New staff username: ");
    string password = input("Password (minimum 8 characters): ");
    string role = input("Role (receptionist/approver): ");
    if (username.empty() || password.size() < 8 ||
        (role != "receptionist" && role != "approver")) {
        cout << "Invalid details. Check username, password length and role.\n";
        return false;
    }

    string salt, hash;
    if (!makePasswordHash(password, salt, hash)) return false;
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "INSERT INTO users(username,salt,password_hash,role) VALUES(?,?,?,?)";
    sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, salt.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, role.c_str(), -1, SQLITE_TRANSIENT);
    bool ok = sqlite3_step(stmt) == SQLITE_DONE;
    cout << (ok ? "Staff account created.\n" : "Could not create staff account. Username may exist.\n");
    sqlite3_finalize(stmt);
    return ok;
}

void listUsers() {
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db, "SELECT id,username,role FROM users ORDER BY id", -1, &stmt, nullptr);
    cout << "\nID\tUSERNAME\tROLE\n";
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        cout << sqlite3_column_int(stmt, 0) << "\t"
             << sqlite3_column_text(stmt, 1) << "\t\t"
             << sqlite3_column_text(stmt, 2) << "\n";
    }
    sqlite3_finalize(stmt);
}

void addPatient() {
    string name = input("Patient name: ");
    int age = numberInput("Age: ");
    string gender = input("Gender: ");
    string phone = input("Phone: ");
    if (name.empty() || age < 0 || age > 120 || gender.empty() || phone.empty()) {
        cout << "Invalid patient details.\n"; return;
    }
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db, "INSERT INTO patients(name,age,gender,phone) VALUES(?,?,?,?)",
                       -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, age);
    sqlite3_bind_text(stmt, 3, gender.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, phone.c_str(), -1, SQLITE_TRANSIENT);
    cout << (sqlite3_step(stmt) == SQLITE_DONE ? "Patient added.\n" : "Could not add patient.\n");
    sqlite3_finalize(stmt);
}

void listPatients() {
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db, "SELECT id,name,age,gender,phone FROM patients ORDER BY id",
                       -1, &stmt, nullptr);
    cout << "\nID\tNAME\t\tAGE\tGENDER\tPHONE\n";
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        cout << sqlite3_column_int(stmt, 0) << "\t"
             << sqlite3_column_text(stmt, 1) << "\t"
             << sqlite3_column_int(stmt, 2) << "\t"
             << sqlite3_column_text(stmt, 3) << "\t"
             << sqlite3_column_text(stmt, 4) << "\n";
    }
    sqlite3_finalize(stmt);
}

void updatePatient() {
    int id = numberInput("Patient ID to update: ");
    string name = input("New name: ");
    int age = numberInput("New age: ");
    string gender = input("New gender: ");
    string phone = input("New phone: ");
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db, "UPDATE patients SET name=?,age=?,gender=?,phone=? WHERE id=?",
                       -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, age);
    sqlite3_bind_text(stmt, 3, gender.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, phone.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 5, id);
    bool ok = sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(db) > 0;
    cout << (ok ? "Patient updated.\n" : "Patient ID not found.\n");
    sqlite3_finalize(stmt);
}

void deletePatient() {
    int id = numberInput("Patient ID to delete: ");
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db, "DELETE FROM patients WHERE id=?", -1, &stmt, nullptr);
    sqlite3_bind_int(stmt, 1, id);
    bool ok = sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(db) > 0;
    cout << (ok ? "Patient deleted.\n" : "Patient ID not found (or has appointments).\n");
    sqlite3_finalize(stmt);
}

void addDoctor() {
    string name = input("Doctor name: ");
    string specialization = input("Specialization: ");
    string phone = input("Phone: ");
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db, "INSERT INTO doctors(name,specialization,phone) VALUES(?,?,?)",
                       -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, specialization.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, phone.c_str(), -1, SQLITE_TRANSIENT);
    cout << (sqlite3_step(stmt) == SQLITE_DONE ? "Doctor added.\n" : "Could not add doctor.\n");
    sqlite3_finalize(stmt);
}

void listDoctors() {
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db, "SELECT id,name,specialization,phone FROM doctors ORDER BY id",
                       -1, &stmt, nullptr);
    cout << "\nID\tDOCTOR\t\tSPECIALIZATION\tPHONE\n";
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        cout << sqlite3_column_int(stmt, 0) << "\t"
             << sqlite3_column_text(stmt, 1) << "\t"
             << sqlite3_column_text(stmt, 2) << "\t"
             << sqlite3_column_text(stmt, 3) << "\n";
    }
    sqlite3_finalize(stmt);
}

void addAppointment() {
    int patientId = numberInput("Patient ID: ");
    int doctorId = numberInput("Doctor ID: ");
    string date = input("Appointment date/time (e.g. 2026-11-20 10:30): ");
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "INSERT INTO appointments(patient_id,doctor_id,appointment_date) VALUES(?,?,?)";
    sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    sqlite3_bind_int(stmt, 1, patientId);
    sqlite3_bind_int(stmt, 2, doctorId);
    sqlite3_bind_text(stmt, 3, date.c_str(), -1, SQLITE_TRANSIENT);
    bool ok = sqlite3_step(stmt) == SQLITE_DONE;
    cout << (ok ? "Appointment created with Pending status.\n"
                : "Could not create appointment. Check patient and doctor IDs.\n");
    sqlite3_finalize(stmt);
}

void listAppointments() {
    const char* sql =
        "SELECT a.id,p.name,d.name,a.appointment_date,a.status "
        "FROM appointments a JOIN patients p ON a.patient_id=p.id "
        "JOIN doctors d ON a.doctor_id=d.id ORDER BY a.appointment_date";
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    cout << "\nID\tPATIENT\t\tDOCTOR\t\tDATE/TIME\t\tSTATUS\n";
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        cout << sqlite3_column_int(stmt, 0) << "\t"
             << sqlite3_column_text(stmt, 1) << "\t"
             << sqlite3_column_text(stmt, 2) << "\t"
             << sqlite3_column_text(stmt, 3) << "\t"
             << sqlite3_column_text(stmt, 4) << "\n";
    }
    sqlite3_finalize(stmt);
}

void updateAppointmentStatus() {
    int id = numberInput("Appointment ID: ");
    string status = input("New status (Approved/Rejected): ");
    if (status != "Approved" && status != "Rejected") {
        cout << "Status must be Approved or Rejected.\n"; return;
    }
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db, "UPDATE appointments SET status=? WHERE id=?", -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, status.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, id);
    bool ok = sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(db) > 0;
    cout << (ok ? "Appointment status updated.\n" : "Appointment ID not found.\n");
    sqlite3_finalize(stmt);
}

void adminMenu() {
    while (true) {
        cout << "\n--- ADMIN MENU ---\n"
             << "1. Add staff account\n2. List staff accounts\n"
             << "3. Add patient\n4. List patients\n5. Update patient\n6. Delete patient\n"
             << "7. Add doctor\n8. List doctors\n"
             << "9. Create appointment\n10. List appointments\n"
             << "11. Approve/Reject appointment\n0. Logout\n";
        int c = numberInput("Choice: ");
        switch (c) {
            case 1: addUser(); break;
            case 2: listUsers(); break;
            case 3: addPatient(); break;
            case 4: listPatients(); break;
            case 5: updatePatient(); break;
            case 6: deletePatient(); break;
            case 7: addDoctor(); break;
            case 8: listDoctors(); break;
            case 9: addAppointment(); break;
            case 10: listAppointments(); break;
            case 11: updateAppointmentStatus(); break;
            case 0: return;
            default: cout << "Invalid choice.\n";
        }
    }
}

void receptionistMenu() {
    while (true) {
        cout << "\n--- RECEPTIONIST MENU ---\n"
             << "1. Add patient\n2. List patients\n"
             << "3. List doctors\n4. Create appointment\n5. List appointments\n0. Logout\n";
        int c = numberInput("Choice: ");
        switch (c) {
            case 1: addPatient(); break;
            case 2: listPatients(); break;
            case 3: listDoctors(); break;
            case 4: addAppointment(); break;
            case 5: listAppointments(); break;
            case 0: return;
            default: cout << "Invalid choice.\n";
        }
    }
}

void approverMenu() {
    while (true) {
        cout << "\n--- APPROVER MENU ---\n"
             << "1. View appointments\n2. Approve/Reject appointment\n0. Logout\n";
        int c = numberInput("Choice: ");
        switch (c) {
            case 1: listAppointments(); break;
            case 2: updateAppointmentStatus(); break;
            case 0: return;
            default: cout << "Invalid choice.\n";
        }
    }
}

int main() {
    if (sqlite3_open("hospital.db", &db) != SQLITE_OK) {
        cerr << "Unable to open database.\n";
        return 1;
    }

    if (!initializeDatabase()) {
        sqlite3_close(db);
        return 1;
    }

    createFirstAdmin();

    while (true) {
        User user{};
        if (!login(user)) {
            string again = input("Try again? (y/n): ");
            if (again != "y" && again != "Y") break;
            continue;
        }

        cout << "\nWelcome, " << user.username << " (" << user.role << ")\n";
        if (user.role == "admin") adminMenu();
        else if (user.role == "receptionist") receptionistMenu();
        else if (user.role == "approver") approverMenu();
    }

    sqlite3_close(db);
    cout << "Application closed. Data is saved in hospital.db\n";
    return 0;
}
