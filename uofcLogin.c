#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#define MAX_INPUT 100
#define MAX_QUERY 256
#define MAX_INPUT_ATTEMPTS 3

typedef struct {
    const int IT_ACCOUNT;
    const int EID_ACCOUNT;
    const int ADMIN_ACCOUNT;
} LoginType;

static const LoginType LOGIN_TYPE = {1, 2, 3};

// declarations
int vulnerableAuthenticate(sqlite3 *db, const char *eid, const char *username, const char *password, int loginType);
void clearScreen();
int getEIdInputs(char *eid, char *password);
int getUsernameAndPasswordInputs(char *username, char *password);
void showWelcomeMessage();
void showEnrollmentMenu();
void showMainMenu_ItAccount();
int getLoginType();
void showEnrollmentInfo(sqlite3 *db, const char *username, const char *semester);
void addCourse(sqlite3 *db, const char *username, const char *semester);
void dropCourse(sqlite3 *db, const char *username, const char *semester);
void showPersonalInfo(sqlite3 *db, const char *eid, const char *username, int loginType);
void showPayrollHistory(sqlite3 *db, const char *username);
void showMainMenu_EIdAccount();
void showApplication(sqlite3 *db, const char *eid);
void createNewApplication(sqlite3 *db, const char *eid);
void showTranscript(sqlite3 *db, const char *eid);
void handlePayrollMenu(sqlite3 *db, const char *username);
void handleMainMenu_ITAccount(sqlite3 *db, const char *username, int loginType);
void handleMainMenu_EIdAccount(sqlite3 *db, const char *eid, int loginType);
const char* getSemesterString(int choice);
void showAvailableCourses(sqlite3 *db, const char *semester);
int isCourseAvailable(sqlite3 *db, const char *courseCode, const char *semester);
int isAlreadyEnrolled(sqlite3 *db, const char *username, const char *courseCode, const char *semester);
void showBankAccountDetails(sqlite3 *db, const char *username);
void updateBankAccount(sqlite3 *db, const char *username);

/**
 * COMMON METHODS
 */
int vulnerableAuthenticate(sqlite3 *db, const char *eid, const char *username, const char *password, int loginType) {
    char query[MAX_QUERY];
    sqlite3_stmt *stmt;
    int result = 0;
    
    // VULNERABILITY
    // CWE 89 - SQL injection vulnerabilit because of string concatenation in the query
    if (loginType == LOGIN_TYPE.EID_ACCOUNT) {
        snprintf(query, sizeof(query), "SELECT * FROM users_eid WHERE eid='%s' AND password='%s'", eid, password);
    } 
    else if (loginType == LOGIN_TYPE.IT_ACCOUNT) {
        snprintf(query, sizeof(query), "SELECT * FROM users_it_account WHERE username='%s' AND password='%s'", username, password);
    } 
    else {
        snprintf(query, sizeof(query), "SELECT * FROM admin_users WHERE username='%s' AND password='%s'", username, password);
    }
        
    int rc = sqlite3_prepare_v2(db, query, -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[ERROR] Internal Server Error - Failed to fetch data: %s\n", sqlite3_errmsg(db));
        return 0;
    }
    
    rc = sqlite3_step(stmt);

    // VULNERABILITY
    //CWE-287 - checking if query returns any rows is weak authentication, there's no secure password hashing/salting either
    if (rc == SQLITE_ROW) {
        result = 1;  // Authentication successful
    }
    
    sqlite3_finalize(stmt);
    return result;
}

void clearScreen(){
    system("clear");
}

void showWelcomeMessage(){
    const char* WELCOME_ASCII = "\
    /***\n\
    *     __    __  _______  ___      _______  _______  __   __  _______    _______  _______    __   __  _______  _______  _______ \n\
    *    |  |  |  ||       ||   |    |       ||       ||  |_|  ||       |  |       ||       |  |  | |  ||       ||       ||   ____|\n\
    *    |  |  |  ||    ___||   |    |    ___||   _   ||       ||    ___|  |_     _||   _   |  |  | |  ||   _   ||    ___||  |    \n\
    *    |  |/\\|  ||   |___ |   |    |   |___ |  | |  ||       ||   |___     |   |  |  | |  |  |  |_|  ||  | |  ||   |___ |  |     \n\
    *    |        ||    ___||   |___ |    ___||  |_|  ||       ||    ___|    |   |  |  |_|  |  |       ||  |_|  ||    ___||  |    \n\
    *    |   /\\   ||   |___ |       ||   |___ |       || ||_|| ||   |___     |   |  |       |  |       ||       ||   |    |  |____\n\
    *    |__/  \\__||_______||_______||_______||_______||_|   |_||_______|    |___|  |_______|  |_______||_______||___|    |_______|\n\
    ***/\n";

    clearScreen();
    printf("%s\n", WELCOME_ASCII);
    printf("\n");
}

int getLoginType(){
    int selectedOption;
    int loginAttemps = 0;
    do {
        showWelcomeMessage();
        printf("1. Log in with your IT Account (For current students)\n");
        printf("2. Log in with your eID (For student applicants, alumni, and guests)\n");
        printf("3. Log in as Admin\n\n");
        printf("Please select option (1, 2 or 3): ");

        scanf("%d", &selectedOption);
        loginAttemps++;

        if(selectedOption != 1 && selectedOption != 2 && selectedOption != 3) {
            printf("\n[ERROR] INVALID OPTION SELECTED !!");
            if(loginAttemps >= MAX_INPUT_ATTEMPTS) {
                return -1;
            }
            printf("\nPlease select from the given options only.");
            printf("\nPress Enter to continue...");
            getchar();
            getchar();
            printf("=========================================\n\n");
        }
    } while((selectedOption != 1 && selectedOption != 2 && selectedOption != 3) && (loginAttemps < MAX_INPUT_ATTEMPTS));

    return selectedOption;
}

void showPersonalInfo(sqlite3 *db, const char *eid, const char *username, int loginType) {
    sqlite3_stmt *stmt;
    char query[MAX_QUERY];
    
    printf("\n----------------------------------------");
    printf("\nPersonal Information:\n");
    printf("----------------------------------------\n");
    
    if(loginType == LOGIN_TYPE.EID_ACCOUNT){
        snprintf(query, sizeof(query), "SELECT eid, firstName, lastName, email FROM users_eid WHERE eid = ?");
    } 
    else {
        snprintf(query, sizeof(query), "SELECT username, firstName, lastName, email FROM users_it_account WHERE username = ?");
    }
    
    if(sqlite3_prepare_v2(db, query, -1, &stmt, 0) == SQLITE_OK){
        if(loginType == LOGIN_TYPE.EID_ACCOUNT){
            sqlite3_bind_text(stmt, 1, eid, -1, SQLITE_STATIC);
        } 
        else {
            sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
        }
        
        if(sqlite3_step(stmt) == SQLITE_ROW){
            if(loginType == LOGIN_TYPE.EID_ACCOUNT){
                printf("ID: %s\n", sqlite3_column_text(stmt, 0));
            }
            else {
                printf("Username: %s\n", sqlite3_column_text(stmt, 0));
            }
            printf("First Name: %s\n", sqlite3_column_text(stmt, 1));
            printf("Last Name: %s\n", sqlite3_column_text(stmt, 2));
            printf("Email: %s\n", sqlite3_column_text(stmt, 3));
        }
    }
    sqlite3_finalize(stmt);
}

int getUsernameAndPasswordInputs(char *username, char *password) {
    printf("\nEnter Username: ");
    if (fgets(username, MAX_INPUT, stdin) == NULL) return -1;
    username[strcspn(username, "\n")] = 0;
    
    if (strlen(username) == 0) return -1;
    
    printf("Enter Password: ");
    if (fgets(password, MAX_INPUT, stdin) == NULL) return -1;
    password[strcspn(password, "\n")] = 0;
    
    if (strlen(password) == 0) return -1;
    
    return 0;
}

/**
 * eID account flow methods
 */
int getEIdInputs(char *eid, char *password) {
    printf("\nEnter eID: ");
    if (fgets(eid, MAX_INPUT, stdin) == NULL) return -1;
    eid[strcspn(eid, "\n")] = 0;
    
    if (strlen(eid) == 0) return -1;
    
    printf("Enter Password: ");
    if (fgets(password, MAX_INPUT, stdin) == NULL) return -1;
    password[strcspn(password, "\n")] = 0;
    
    if (strlen(password) == 0) return -1;
    
    return 0;
}

void showMainMenu_EIdAccount() {
    showWelcomeMessage();
    printf("\n\n\t\t\t\t============================================================\n");
    printf("\t\t\t\t\t   --- Welcome to your Student Center ---");
    printf("\n\t\t\t\t============================================================\n\n");
    printf("1. View/Create Application\n");
    printf("2. View Transcript\n");
    printf("3. Personal Info\n");
    printf("4. Logout\n\n");
    printf("Please select option (1-4): ");
}

// OPTION 1: VIEW / CREATE APPLICATION
void showApplication(sqlite3 *db, const char *eid) {
    sqlite3_stmt *stmt;
    const char *query = "SELECT id, applicationDate, program, status, gpa, previousDegree, "
                       "university, graduationYear, remarks FROM applications WHERE eid = ?";
    
    if (sqlite3_prepare_v2(db, query, -1, &stmt, 0) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, eid, -1, SQLITE_STATIC);
        
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            printf("\n----------------------------------------");
            printf("\nApplication Details:\n");
            printf("----------------------------------------\n");
            printf("Application ID: %d\n", sqlite3_column_int(stmt, 0));
            printf("Date Applied: %s\n", sqlite3_column_text(stmt, 1));
            printf("Program: %s\n", sqlite3_column_text(stmt, 2));
            printf("Status: %s\n", sqlite3_column_text(stmt, 3));
            printf("GPA: %.2f\n", sqlite3_column_double(stmt, 4));
            printf("Previous Degree: %s\n", sqlite3_column_text(stmt, 5));
            printf("University: %s\n", sqlite3_column_text(stmt, 6));
            printf("Graduation Year: %s\n", sqlite3_column_text(stmt, 7));
            
            const char* remarks = (const char*)sqlite3_column_text(stmt, 8);
            if (remarks) {
                printf("\nRemarks: %s\n", remarks);
            }
        } else {
            printf("\nNo existing application found.\n");
            printf("Would you like to create a new application? (y/n): ");
            char choice;
            scanf(" %c", &choice);
            getchar(); // Clear buffer
            
            if (choice == 'y' || choice == 'Y') {
                createNewApplication(db, eid);
            }
        }
    }
    sqlite3_finalize(stmt);
}

void createNewApplication(sqlite3 *db, const char *eid) {
    char program[MAX_INPUT];
    char prevDegree[MAX_INPUT];
    char university[MAX_INPUT];
    char gradYear[MAX_INPUT];
    double gpa;
    sqlite3_stmt *stmt;
    
    printf("\n----------------------------------------");
    printf("\nNew Application Form:\n");
    printf("----------------------------------------\n");
    
    printf("Enter Program (e.g., Masters in Computer Science): ");
    fgets(program, MAX_INPUT, stdin);
    program[strcspn(program, "\n")] = 0;
    
    printf("Enter GPA: ");
    scanf("%lf", &gpa);
    getchar(); // Clear buffer
    
    printf("Enter Previous Degree: ");
    fgets(prevDegree, MAX_INPUT, stdin);
    prevDegree[strcspn(prevDegree, "\n")] = 0;
    
    printf("Enter University: ");
    fgets(university, MAX_INPUT, stdin);
    university[strcspn(university, "\n")] = 0;
    
    printf("Enter Graduation Year: ");
    fgets(gradYear, MAX_INPUT, stdin);
    gradYear[strcspn(gradYear, "\n")] = 0;
    
    const char *query = "INSERT INTO applications (eid, applicationDate, program, gpa, "
                       "previousDegree, university, graduationYear) "
                       "VALUES (?, date('now'), ?, ?, ?, ?, ?)";
    
    if (sqlite3_prepare_v2(db, query, -1, &stmt, 0) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, eid, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, program, -1, SQLITE_STATIC);
        sqlite3_bind_double(stmt, 3, gpa);
        sqlite3_bind_text(stmt, 4, prevDegree, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 5, university, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 6, gradYear, -1, SQLITE_STATIC);
        
        if (sqlite3_step(stmt) == SQLITE_DONE) {
            printf("\nApplication submitted successfully!\n");
        } else {
            printf("\nError submitting application: %s\n", sqlite3_errmsg(db));
        }
    }
    sqlite3_finalize(stmt);
}

// OPTION 2: VIEW TRANSCRIPT
void showTranscript(sqlite3 *db, const char *eid) {
    sqlite3_stmt *stmt;
    const char *query = "SELECT courseCode, courseName, grade, creditHours, semester "
                       "FROM transcripts WHERE eid = ? ORDER BY semester DESC";
    
    printf("\n--------------------------------------------------------------------------------");
    printf("\nAcademic Transcript:\n");
    printf("--------------------------------------------------------------------------------\n");
    
    if (sqlite3_prepare_v2(db, query, -1, &stmt, 0) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, eid, -1, SQLITE_STATIC);
        
        printf("%-12s %-35s %-6s %-6s %-15s\n", 
               "Course Code", "Course Name", "Grade", "Hours", "Semester");
        printf("--------------------------------------------------------------------------------\n");
        
        int found = 0;
                
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            found = 1;
            printf("%-12s %-35s %-6s %-6d %-15s\n",
                   sqlite3_column_text(stmt, 0),
                   sqlite3_column_text(stmt, 1),
                   sqlite3_column_text(stmt, 2),
                   sqlite3_column_int(stmt, 3),
                   sqlite3_column_text(stmt, 4));
        }
        
        if (found) {
            printf("\n--------------------------------------------------------------------------------");
        } else {
            printf("\n -- No records found. --\n");
        }
    }
    sqlite3_finalize(stmt);
}


/**
 *  IT account flow methods
 */
void showMainMenu_ItAccount() {
    showWelcomeMessage();
    printf("\n\n\t\t\t\t============================================================\n");
    printf("\t\t\t\t\t   --- Welcome to your Student Center ---");
    printf("\n\t\t\t\t============================================================\n\n");
    printf("1. Enrollment Info\n");
    printf("2. Personal Info\n");
    printf("3. Payroll Details\n");
    printf("4. Logout\n\n");
    printf("Please select option (1-4): ");
}

// OPTION 1: ENROLLMENT INFO
void showEnrollmentMenu() {
    showMainMenu_ItAccount();
    printf("\n\nSelect Semester:\n");
    printf("1. Fall 2024\n");
    printf("2. Winter 2025\n");
    printf("3. Spring 2025\n");
    printf("4. Summer 2025\n");
    printf("5. Back to Main Menu\n\n");
    printf("Please select option (1-5): ");
}

const char* getSemesterString(int choice) {
    switch(choice) {
        case 1: return "Fall2024";
        case 2: return "Winter2025";
        case 3: return "Spring2025";
        case 4: return "Summer2025";
        default: return NULL;
    }
}

void showEnrollmentInfo(sqlite3 *db, const char *username, const char *semester) {
    sqlite3_stmt *stmt;
    char query[MAX_QUERY];
    
    printf("\n\n---------------------------------------------------------------");
    printf("\nEnrolled Courses for %s:\n", semester);
    printf("---------------------------------------------------------------\n");
    
    snprintf(query, sizeof(query), 
             "SELECT e.courseCode, c.courseName, c.professor "
             "FROM enrollment e "
             "JOIN courses c ON e.courseCode = c.courseCode AND e.semester = c.semester "
             "WHERE e.username = ? AND e.semester = ?");
    
    if (sqlite3_prepare_v2(db, query, -1, &stmt, 0) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, semester, -1, SQLITE_STATIC);
        
        printf("%-10s %-35s %-20s\n", "Code", "Course Name", "Professor");
        printf("---------------------------------------------------------------\n");
        
        int found = 0;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            found = 1;
            printf("%-10s %-35s %-20s\n", sqlite3_column_text(stmt, 0), sqlite3_column_text(stmt, 1), sqlite3_column_text(stmt, 2));
        }
        printf("\n---------------------------------------------------------------\n\n");   

        if (!found) {
            printf("\n -- No courses enrolled for %s -- \n", semester);
        }
    }
    sqlite3_finalize(stmt);
    
    printf("\n1. Add Course\n");
    printf("2. Drop Course\n");
    printf("3. Back to Main Menu\n");
    printf("\nSelect option (1-3): ");
}

void showAvailableCourses(sqlite3 *db, const char *semester) {
    sqlite3_stmt *stmt;
    char query[MAX_QUERY];
    
    printf("\n---------------------------------------------------------------");
    printf("\nAvailable Courses for %s:\n", semester);
    printf("---------------------------------------------------------------\n");
    
    snprintf(query, sizeof(query), "SELECT courseCode, courseName, professor FROM courses WHERE semester = ?");
    
    if (sqlite3_prepare_v2(db, query, -1, &stmt, 0) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, semester, -1, SQLITE_STATIC);
        
        printf("%-10s %-35s %-20s\n", "Code", "Course Name", "Professor");
        printf("---------------------------------------------------------------\n");

        int found = 0;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            found = 1;
            printf("%-10s %-35s %-20s\n", sqlite3_column_text(stmt, 0), sqlite3_column_text(stmt, 1), sqlite3_column_text(stmt, 2));
        }
        printf("\n---------------------------------------------------------------\n\n");   
        
        if (!found) {
            printf("\n -- No courses available for %s\n -- ", semester);
        }
    }
    sqlite3_finalize(stmt);
}

int isCourseAvailable(sqlite3 *db, const char *courseCode, const char *semester) {
    sqlite3_stmt *stmt;
    char query[MAX_QUERY];
    int available = 0;
    
    snprintf(query, sizeof(query), "SELECT * FROM courses WHERE courseCode = ? AND semester = ? LIMIT 1");
    
    if (sqlite3_prepare_v2(db, query, -1, &stmt, 0) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, courseCode, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, semester, -1, SQLITE_STATIC);
        
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            available = 1;
        }
    }
    sqlite3_finalize(stmt);
    return available;
}

int isAlreadyEnrolled(sqlite3 *db, const char *username, const char *courseCode, const char *semester) {
    sqlite3_stmt *stmt;
    char query[MAX_QUERY];
    int enrolled = 0;
    
    snprintf(query, sizeof(query), 
             "SELECT 1 FROM enrollment WHERE username = ? AND courseCode = ? AND semester = ?");
    
    if (sqlite3_prepare_v2(db, query, -1, &stmt, 0) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, courseCode, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, semester, -1, SQLITE_STATIC);
        
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            enrolled = 1;
        }
    }
    sqlite3_finalize(stmt);
    return enrolled;
}

void addCourse(sqlite3 *db, const char *username, const char *semester) {
    char courseCode[MAX_INPUT];
    sqlite3_stmt *stmt;
    char query[MAX_QUERY];
    
    // Check if there are any courses open for enrollment
    snprintf(query, sizeof(query), "SELECT COUNT(*) FROM courses WHERE semester = ?");
             
    if (sqlite3_prepare_v2(db, query, -1, &stmt, 0) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, semester, -1, SQLITE_STATIC);
        
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            int courseCount = sqlite3_column_int(stmt, 0);
            if (courseCount == 0) {
                printf("\nNo courses available for enrollment in %s\n", semester);
                sqlite3_finalize(stmt);
                printf("\nPress Enter to continue...");
                getchar();
                return;
            }
        }
    }
    sqlite3_finalize(stmt);
    
    // Show available courses for the selected semester
    showAvailableCourses(db, semester);
    
    printf("\nEnter Course Code to enroll (or 'q' to cancel): ");
    scanf("%s", courseCode);
    getchar();
    
    if (strcmp(courseCode, "q") == 0) {
        return;
    }
    
    // Check if course exists and is available
    if (!isCourseAvailable(db, courseCode, semester)) {
        printf("\nError: Course %s is not available for %s\n", courseCode, semester);
        printf("\nPress Enter to continue...");
        getchar();
        return;
    }
    
    // Check if already enrolled
    if (isAlreadyEnrolled(db, username, courseCode, semester)) {
        printf("\nError: You are already enrolled in %s\n", courseCode);
        printf("\nPress Enter to continue...");
        getchar();
        return;
    }
    
    // Add enrollment
    snprintf(query, sizeof(query), "INSERT INTO enrollment (username, courseCode, semester) VALUES (?, ?, ?)");
    
    if(sqlite3_prepare_v2(db, query, -1, &stmt, 0) == SQLITE_OK){
        sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, courseCode, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, semester, -1, SQLITE_STATIC);
        
        if(sqlite3_step(stmt) == SQLITE_DONE){
            printf("\nSuccessfully enrolled in %s!\n", courseCode);
        } 
        else {
            printf("\nError enrolling in course: %s\n", sqlite3_errmsg(db));
        }
    }
    sqlite3_finalize(stmt);
    
    printf("\nPress Enter to continue...");
    getchar();
}

void dropCourse(sqlite3 *db, const char *username, const char *semester) {
    char courseCode[MAX_INPUT];
    char query[MAX_QUERY];
    sqlite3_stmt *stmt;
    
    printf("\nEnter Course Code to drop (or 'q' to cancel): ");
    scanf("%s", courseCode);
    getchar();
    
    if(strcmp(courseCode, "q") == 0){
        return;
    }
    
    // Check if course user trying to drop
    snprintf(query, sizeof(query), "SELECT * FROM enrollment WHERE username = ? AND courseCode = ? AND semester = ?");
             
    if (sqlite3_prepare_v2(db, query, -1, &stmt, 0) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, courseCode, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, semester, -1, SQLITE_STATIC);
        
        if (sqlite3_step(stmt) != SQLITE_ROW) {
            printf("\nError: You are not enrolled in %s for %s\n", courseCode, semester);
            sqlite3_finalize(stmt);
            printf("\nPress Enter to continue...");
            getchar();
            return;
        }
        sqlite3_finalize(stmt);
    }
    
    // Drop the course
    snprintf(query, sizeof(query), "DELETE FROM enrollment WHERE username = ? AND courseCode = ? AND semester = ?");
    
    if (sqlite3_prepare_v2(db, query, -1, &stmt, 0) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, courseCode, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, semester, -1, SQLITE_STATIC);
        
        if (sqlite3_step(stmt) == SQLITE_DONE) {
            printf("\nSuccessfully dropped %s!\n", courseCode);
        } else {
            printf("\nError dropping course: %s\n", sqlite3_errmsg(db));
        }
    }
    sqlite3_finalize(stmt);
    
    printf("\nPress Enter to continue...");
    getchar();
}

// OPTION 3: PAYROLL DETAILS
void handlePayrollMenu(sqlite3 *db, const char *username) {
    int choice;
    do {
        showMainMenu_ItAccount();
        showPayrollHistory(db, username);
        scanf("%d", &choice);
        getchar(); // Clear buffer

        switch(choice) {
            case 1:
                showBankAccountDetails(db, username);
                printf("\nPress Enter to continue...");
                getchar();
                break;
            
            case 2:
                updateBankAccount(db, username);
                printf("\nPress Enter to continue...");
                getchar();
                break;
                
            case 3:
                break;
                
            default:
                printf("\nInvalid option! Please try again.\n");
                printf("\nPress Enter to continue...");
                getchar();
        }
    } while (choice != 3);
}

void showPayrollHistory(sqlite3 *db, const char *username) {
    sqlite3_stmt *stmt;
    char query[MAX_QUERY];
    
    printf("\n\n----------------------------------------");
    printf("\nPayroll History:\n");
    printf("----------------------------------------\n");
    
    // Get payment history with bank details
    snprintf(query, sizeof(query), 
             "SELECT p.payDate, p.amount, p.description, "
             "b.bankName, b.accountNumber "
             "FROM payroll p "
             "LEFT JOIN bank_accounts b ON p.bankAccountId = b.id "
             "WHERE p.username = ? "
             "ORDER BY p.payDate DESC");
    
    if (sqlite3_prepare_v2(db, query, -1, &stmt, 0) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
        
        printf("%-12s %-12s %-20s %-15s %-15s\n", 
               "Date", "Amount", "Description", "Bank", "Account");
        printf("----------------------------------------------------------------------------\n");
        
        int found = 0;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            found = 1;
            printf("%-12s $%-11.2f %-20s %-15s *****%s\n",
                   sqlite3_column_text(stmt, 0),
                   sqlite3_column_double(stmt, 1),
                   sqlite3_column_text(stmt, 2),
                   sqlite3_column_text(stmt, 3),
                   sqlite3_column_text(stmt, 4) ? 
                   ((const char*)sqlite3_column_text(stmt, 4) + strlen((const char*)sqlite3_column_text(stmt, 4)) - 4) : 
                   "N/A");
        }
        printf("\n---------------------------------------------------------------\n\n");   

        if (!found) {
            printf("\n -- No payment records found. -- \n");
        }
    }
    sqlite3_finalize(stmt);
    
    printf("\n1. View Bank Account Details\n");
    printf("2. Update Bank Account Details\n");
    printf("3. Back to Main Menu\n");
    printf("\nSelect option (1-3): ");
}

void showBankAccountDetails(sqlite3 *db, const char *username) {
    sqlite3_stmt *stmt;
    char query[MAX_QUERY];
    
    printf("\n----------------------------------------");
    printf("\nBank Account Details:\n");
    printf("----------------------------------------\n");
    
    snprintf(query, sizeof(query), "SELECT id, bankName, accountNumber, routingNumber, accountType, isActive "
             "FROM bank_accounts WHERE username = ?");
    
    if(sqlite3_prepare_v2(db, query, -1, &stmt, 0) == SQLITE_OK){
        sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
        
        int found = 0;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            found = 1;
            printf("Account ID: %d\n", sqlite3_column_int(stmt, 0));
            printf("Bank Name: %s\n", sqlite3_column_text(stmt, 1));
            printf("Account Number: %s\n", sqlite3_column_text(stmt, 2));
            printf("Routing Number: %s\n", sqlite3_column_text(stmt, 3));
            printf("Account Type: %s\n", sqlite3_column_text(stmt, 4));
            printf("Status: %s\n", sqlite3_column_int(stmt, 5) ? "Active" : "Inactive");
        }
        
        if (!found) {
            printf("No bank account details found.\n");
        }
    }
    sqlite3_finalize(stmt);
}

void updateBankAccount(sqlite3 *db, const char *username) {
    char bank_name[MAX_INPUT];
    char account_number[MAX_INPUT];
    char routing_number[MAX_INPUT];
    char account_type[MAX_INPUT];
    sqlite3_stmt *stmt;
    char query[MAX_QUERY];
    
    printf("\nUpdate Bank Account Details\n");
    printf("----------------------------------------\n");
    
    printf("Enter Bank Name: ");
    fgets(bank_name, MAX_INPUT, stdin);
    bank_name[strcspn(bank_name, "\n")] = 0;
    
    printf("Enter Account Number: ");
    fgets(account_number, MAX_INPUT, stdin);
    account_number[strcspn(account_number, "\n")] = 0;
    
    printf("Enter Routing Number: ");
    fgets(routing_number, MAX_INPUT, stdin);
    routing_number[strcspn(routing_number, "\n")] = 0;
    
    printf("Enter Account Type (Checking/Savings): ");
    fgets(account_type, MAX_INPUT, stdin);
    account_type[strcspn(account_type, "\n")] = 0;
    
    // Check if we need to update or insert
    snprintf(query, sizeof(query), "SELECT id FROM bank_accounts WHERE username = ?");
             
    if (sqlite3_prepare_v2(db, query, -1, &stmt, 0) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
        
        if(sqlite3_step(stmt) == SQLITE_ROW){
            // Update existing account
            snprintf(query, sizeof(query), "UPDATE bank_accounts SET bankName = ?, accountNumber = ?, "
                     "routingNumber = ?, accountType = ? WHERE username = ?");
        } 
        else {
            // Insert new account
            snprintf(query, sizeof(query), "INSERT INTO bank_accounts (bankName, accountNumber, routingNumber, "
                     "accountType, username) VALUES (?, ?, ?, ?, ?)");
        }
    }
    sqlite3_finalize(stmt);
    
    if (sqlite3_prepare_v2(db, query, -1, &stmt, 0) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, bank_name, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, account_number, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, routing_number, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 4, account_type, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 5, username, -1, SQLITE_STATIC);
        
        if(sqlite3_step(stmt) == SQLITE_DONE){
            printf("\nBank account details updated successfully!\n");
        } else {
            printf("\nError updating bank details: %s\n", sqlite3_errmsg(db));
        }
    }
    sqlite3_finalize(stmt);
}


/**
 * Admin flow methods
 */
void showMainMenu_adminAccount(){
    showWelcomeMessage();
    printf("\n\n\t\t\t\t============================================================\n");
    printf("\t\t\t\t\t--- Welcome to Student Center (Admin Account) ---");
    printf("\n\t\t\t\t============================================================\n\n");
    printf("1. Manage Courses\n");
    printf("2. Review Applications\n");
    printf("3. Logout\n\n");
    printf("Please select option (1-3): ");
}

void viewAllCourses(sqlite3 *db) {
    sqlite3_stmt *stmt;
    const char *query = "SELECT courseCode, courseName, professor, semester FROM courses ORDER BY semester, courseCode";
    
    printf("\n--------------------------------------------------------------------------------");
    printf("\nAll Courses:\n");
    printf("--------------------------------------------------------------------------------\n");
    printf("%-12s %-35s %-20s %-15s\n", "Code", "Course Name", "Professor", "Semester");
    printf("--------------------------------------------------------------------------------\n");
    
    if (sqlite3_prepare_v2(db, query, -1, &stmt, 0) == SQLITE_OK) {
        int found = 0;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            found = 1;
            printf("%-12s %-35s %-20s %-15s\n",
                   sqlite3_column_text(stmt, 0),
                   sqlite3_column_text(stmt, 1),
                   sqlite3_column_text(stmt, 2),
                   sqlite3_column_text(stmt, 3));
        }
        printf("\n--------------------------------------------------------------------------------\n\n");   
        
        if (!found) {
            printf("\n -- No courses available --");
        }
    }
    sqlite3_finalize(stmt);
}

void addNewCourse(sqlite3 *db) {
    char courseCode[MAX_INPUT];
    char courseName[MAX_INPUT];
    char professor[MAX_INPUT];
    char semester[MAX_INPUT];
    sqlite3_stmt *stmt;
    
    printf("\nAdd New Course:\n");
    printf("----------------------------------------\n");
    
    printf("Enter Course Code: ");
    fgets(courseCode, MAX_INPUT, stdin);
    courseCode[strcspn(courseCode, "\n")] = 0;
    
    printf("Enter Course Name: ");
    fgets(courseName, MAX_INPUT, stdin);
    courseName[strcspn(courseName, "\n")] = 0;
    
    printf("Enter Professor Name: ");
    fgets(professor, MAX_INPUT, stdin);
    professor[strcspn(professor, "\n")] = 0;
    
    printf("Enter Semester (Fall2024/Winter2025/Spring2025/Summer2025): ");
    fgets(semester, MAX_INPUT, stdin);
    semester[strcspn(semester, "\n")] = 0;
    
    const char *query = "INSERT INTO courses (courseCode, courseName, professor, semester) VALUES (?, ?, ?, ?)";
    
    if (sqlite3_prepare_v2(db, query, -1, &stmt, 0) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, courseCode, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, courseName, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, professor, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 4, semester, -1, SQLITE_STATIC);
        
        if (sqlite3_step(stmt) == SQLITE_DONE) {
            printf("\nCourse added successfully!\n");
        } else {
            printf("\nError adding course: %s\n", sqlite3_errmsg(db));
        }
    }
    sqlite3_finalize(stmt);
}

void removeCourse(sqlite3 *db) {
    viewAllCourses(db);
    
    char courseCode[MAX_INPUT];
    char semester[MAX_INPUT];
    sqlite3_stmt *stmt;
    
    printf("\nRemove Course:\n");
    printf("----------------------------------------\n");
    printf("Enter Course Code to remove (or 'q' to cancel): ");
    fgets(courseCode, MAX_INPUT, stdin);
    courseCode[strcspn(courseCode, "\n")] = 0;

    if (strcmp(courseCode, "q") == 0) {
        printf("\nOperation cancelled.\n");
        return;
    }
    
    printf("Enter Semester: ");
    fgets(semester, MAX_INPUT, stdin);
    semester[strcspn(semester, "\n")] = 0;

    // First verify if the course exists
    const char *checkQuery = "SELECT 1 FROM courses WHERE courseCode = ? AND semester = ?";
    
    if (sqlite3_prepare_v2(db, checkQuery, -1, &stmt, 0) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, courseCode, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, semester, -1, SQLITE_STATIC);
        
        if (sqlite3_step(stmt) != SQLITE_ROW) {
            printf("\n[ERROR] Course '%s' for semester '%s' not found!\n", courseCode, semester);
            sqlite3_finalize(stmt);
            return;
        }
        sqlite3_finalize(stmt);
    }
    
    // If course exists, confirm deletion
    printf("\nAre you sure you want to remove %s for %s? (y/n): ", courseCode, semester);
    char confirm;
    scanf(" %c", &confirm);
    getchar(); // Clear buffer
    
    if (confirm == 'y' || confirm == 'Y') {
        // Check if course is being used in enrollment
        const char *enrollmentCheck = "SELECT 1 FROM enrollment WHERE courseCode = ? AND semester = ?";
        
        if (sqlite3_prepare_v2(db, enrollmentCheck, -1, &stmt, 0) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, courseCode, -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, semester, -1, SQLITE_STATIC);
            
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                printf("\n[ERROR] Cannot delete course - students are currently enrolled!\n");
                sqlite3_finalize(stmt);
                return;
            }
            sqlite3_finalize(stmt);
        }
        
        // Proceed with deletion
        const char *deleteQuery = "DELETE FROM courses WHERE courseCode = ? AND semester = ?";
        
        if (sqlite3_prepare_v2(db, deleteQuery, -1, &stmt, 0) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, courseCode, -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, semester, -1, SQLITE_STATIC);
            
            if (sqlite3_step(stmt) == SQLITE_DONE) {
                int changes = sqlite3_changes(db);
                if (changes > 0) {
                    printf("\n[SUCCESS] Course removed successfully!\n");
                } else {
                    printf("\n[ERROR] Failed to remove course - no matching course found!\n");
                }
            } else {
                printf("\n[ERROR] Database error while removing course: %s\n", sqlite3_errmsg(db));
            }
        }
        sqlite3_finalize(stmt);
    } else {
        printf("\nOperation cancelled.\n");
    }
}

void reviewApplications(sqlite3 *db, const char *adminUsername) {
    sqlite3_stmt *stmt;
    const char *query = "SELECT a.id, a.eid, u.firstName, u.lastName, a.program, "
                       "a.applicationDate, a.status, a.gpa, a.updatedBy "
                       "FROM applications a "
                       "JOIN users_eid u ON a.eid = u.eid "
                       "ORDER BY a.applicationDate DESC";
    
    printf("\n----------------------------------------");
    printf("\nApplications:\n");
    printf("----------------------------------------\n");
    printf("%-5s %-10s %-20s %-30s %-12s %-10s %-18s %-10s\n", 
           "ID", "EID", "Name", "Program", "Date", "Status", "GPA", "Updated By");
    printf("----------------------------------------------------------------------------------------\n");
    
    int applicationsFound = 0;
    if (sqlite3_prepare_v2(db, query, -1, &stmt, 0) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            applicationsFound = 1;
            const char* updatedBy = (const char*)sqlite3_column_text(stmt, 8);
            printf("%-5d %-10s %-20s %-25s %-12s %-10s %-8.2f %-15s\n",
                   sqlite3_column_int(stmt, 0),
                   sqlite3_column_text(stmt, 1),
                   sqlite3_column_text(stmt, 2),
                   sqlite3_column_text(stmt, 4),
                   sqlite3_column_text(stmt, 5),
                   sqlite3_column_text(stmt, 6),
                   sqlite3_column_double(stmt, 7),
                   updatedBy ? updatedBy : "-");
        }
    }
    sqlite3_finalize(stmt);
    
    if (!applicationsFound) {
        printf("\n[INFO] No applications found in the system.\n");
        return;
    }
    
    int appId;
    printf("\nEnter Application ID to review (0 to go back): ");
    scanf("%d", &appId);
    getchar(); // Clear buffer
    
    if (appId <= 0) {
        return;
    }

    // Verify if application exists and get current status
    const char *checkQuery = "SELECT status FROM applications WHERE id = ?";
    if (sqlite3_prepare_v2(db, checkQuery, -1, &stmt, 0) == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, appId);
        
        if (sqlite3_step(stmt) != SQLITE_ROW) {
            printf("\n[ERROR] Application ID %d not found!\n", appId);
            sqlite3_finalize(stmt);
            return;
        }
        
        const char *currentStatus = (const char *)sqlite3_column_text(stmt, 0);
        printf("\nCurrent Status: %s\n", currentStatus);
        sqlite3_finalize(stmt);
    }

    printf("\nChoose action:\n");
    printf("1. Approve\n");
    printf("2. Reject\n");
    printf("3. Mark as Pending\n");
    printf("4. Cancel\n");
    
    int choice;
    printf("\nEnter choice (1-4): ");
    scanf("%d", &choice);
    getchar(); // Clear buffer
    
    if (choice < 1 || choice > 4) {
        printf("\n[ERROR] Invalid choice!\n");
        return;
    }
    
    if (choice == 4) {
        printf("\nOperation cancelled.\n");
        return;
    }
    
    const char *status;
    switch(choice) {
        case 1: status = "Approved"; break;
        case 2: status = "Rejected"; break;
        case 3: status = "Pending"; break;
        default: return;
    }

    const char *updateQuery = "UPDATE applications SET status = ?, updatedBy = ? WHERE id = ?";
    
    if (sqlite3_prepare_v2(db, updateQuery, -1, &stmt, 0) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, status, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, adminUsername, -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 3, appId);
        
        if (sqlite3_step(stmt) == SQLITE_DONE) {
            int changes = sqlite3_changes(db);
            if (changes > 0) {
                printf("\n[SUCCESS] Application status updated successfully!\n");
                
                // Show updated application details
                printf("\nUpdated Application Details:\n");
                printf("----------------------------------------\n");
                const char *detailsQuery = "SELECT a.id, a.eid, u.firstName, u.lastName, "
                                         "a.program, a.status, a.updatedBy "
                                         "FROM applications a "
                                         "JOIN users_eid u ON a.eid = u.eid "
                                         "WHERE a.id = ?";
                
                if (sqlite3_prepare_v2(db, detailsQuery, -1, &stmt, 0) == SQLITE_OK) {
                    sqlite3_bind_int(stmt, 1, appId);
                    
                    if (sqlite3_step(stmt) == SQLITE_ROW) {
                        printf("ID: %d\n", sqlite3_column_int(stmt, 0));
                        printf("EID: %s\n", sqlite3_column_text(stmt, 1));
                        printf("Name: %s %s\n", 
                               sqlite3_column_text(stmt, 2), 
                               sqlite3_column_text(stmt, 3));
                        printf("Program: %s\n", sqlite3_column_text(stmt, 4));
                        printf("Status: %s\n", sqlite3_column_text(stmt, 5));
                        printf("Updated By: %s\n", sqlite3_column_text(stmt, 6));
                    }
                }
            } else {
                printf("\n[ERROR] No changes were made to the application!\n");
            }
        } else {
            printf("\n[ERROR] Failed to update application: %s\n", sqlite3_errmsg(db));
        }
    }
    sqlite3_finalize(stmt);
}

void handleCourseManagement(sqlite3 *db) {
    int choice;
    do {
        showMainMenu_adminAccount();
        printf("\n----------------------------------------");
        printf("\nCourse Management:\n");
        printf("----------------------------------------\n");
        printf("1. View All Courses\n");
        printf("2. Add New Course\n");
        printf("3. Remove Course\n");
        printf("4. Back to Main Menu\n\n");
        printf("Please select option (1-4): ");
        
        scanf("%d", &choice);
        getchar(); // Clear buffer
        
        switch(choice) {
            case 1:
                viewAllCourses(db);
                printf("\nPress Enter to continue...");
                getchar();
                break;
            case 2:
                addNewCourse(db);
                printf("\nPress Enter to continue...");
                getchar();
                break;
            case 3:
                removeCourse(db);
                printf("\nPress Enter to continue...");
                getchar();
                break;
            case 4:
                break;
            default:
                printf("\nInvalid option!\n");
        }
    } while (choice != 4);
    
}

// Main menu after authentication
void handleMainMenu_ITAccount(sqlite3 *db, const char *username, int loginType) {
    int choice;
    do {
        showMainMenu_ItAccount();
        scanf("%d", &choice);
        getchar();

        switch(choice) {
            case 1: { // Enrollment Info
                int semesterChoice;
                do {
                    showEnrollmentMenu();
                    scanf("%d", &semesterChoice);
                    getchar();
                    
                    if (semesterChoice >= 1 && semesterChoice <= 4) {
                        const char *semester = getSemesterString(semesterChoice);
                        int enrollChoice;
                        do {
                            showMainMenu_ItAccount();
                            showEnrollmentInfo(db, username, semester);
                            scanf("%d", &enrollChoice);
                            getchar();
                            
                            switch(enrollChoice) {
                                case 1:
                                    addCourse(db, username, semester);
                                    break;
                                case 2:
                                    dropCourse(db, username, semester);
                                    break;
                                case 3:
                                    break;
                                default:
                                    printf("\nInvalid option! Please try again.\n");
                                    printf("\nPress Enter to continue...");
                                    getchar();
                            }
                        } while (enrollChoice != 3);
                    }
                } while (semesterChoice != 5);
                break;
            }
            
            case 2: // Personal Info
                showPersonalInfo(db, NULL, username, loginType);
                printf("\nPress Enter to continue...");
                getchar();
                break;
            
            case 3: { // Payroll Details
                handlePayrollMenu(db, username);
                break;
            }
            
            case 4: // Logout
                printf("\nLogging out...\n");
                break;
                
            default:
                printf("\nInvalid option! Please try again.\n");
        }
    } while (choice != 4);
}

void handleMainMenu_EIdAccount(sqlite3 *db, const char *eid, int loginType) {
    int choice;
    do {
        showMainMenu_EIdAccount();
        scanf("%d", &choice);
        getchar();

        switch(choice) {
            case 1: { // View/Create Application
                showApplication(db, eid);
                printf("\nPress Enter to continue...");
                getchar();
                break;
            }
            
            case 2: // View transcript
                showTranscript(db, eid);
                printf("\nPress Enter to continue...");
                getchar();
                break;
            
            case 3: { // Personal Info
                showPersonalInfo(db, eid, NULL, loginType);
                printf("\nPress Enter to continue...");
                getchar();
                break;
            }
            
            case 4: // Logout
                printf("\nLogging out...\n");
                break;
                
            default:
                printf("\nInvalid option! Please try again.\n");
                printf("\nPress Enter to continue...");
                getchar();
        }
    } while (choice != 4);
}

void handleMainMenu_AdminAccount(sqlite3 *db, const char *username, int loginType) {
    int choice;
    do {
        showMainMenu_adminAccount();
        scanf("%d", &choice);
        getchar();

        switch(choice) {
            case 1: { // View/Create Application
                handleCourseManagement(db);
                break;
            }
            
            case 2: // review applications
                reviewApplications(db, username);
                printf("\nPress Enter to continue...");
                getchar();
                break;
            
            case 3: // Logout
                printf("\nLogging out...\n");
                break;
                
            default:
                printf("\nInvalid option! Please try again.\n");
                printf("\nPress Enter to continue...");
                getchar();
        }
    } while (choice != 3);
}


int main() {
    char eid[MAX_INPUT] = {0};
    char username[MAX_INPUT] = {0};
    char password[MAX_INPUT] = {0};
    sqlite3 *db;
    
    // Open database
    int rc = sqlite3_open("uofc.db", &db);
    if (rc) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return 1;
    }

    while(1) {
        int selectedOption = getLoginType();
        if (selectedOption == -1) {
            printf("\n[ERROR] Maximum attempts reached. Terminating the program.\n\n");
            sqlite3_close(db);
            return 1;
        }
        
        // Clear input buffer before getting credentials
        int c;
        while ((c = getchar()) != '\n' && c != EOF);
        
        int loginAttempts = 0;
        int authenticated = 0;
        
        // Authentication loop
        while (loginAttempts < MAX_INPUT_ATTEMPTS && !authenticated) {
            // Clear previous credentials
            memset(eid, 0, MAX_INPUT);
            memset(username, 0, MAX_INPUT);
            memset(password, 0, MAX_INPUT);
            
            int inputStatus;
            if(selectedOption == LOGIN_TYPE.EID_ACCOUNT) {
                inputStatus = getEIdInputs(eid, password);
            } else {
                inputStatus = getUsernameAndPasswordInputs(username, password);
            }

            if(inputStatus == -1) {
                printf("\n[ERROR] Invalid input provided.\n");
                loginAttempts++;
                continue;
            }

            authenticated = vulnerableAuthenticate(db, eid, username, password, selectedOption);
            
            if(authenticated) {
                printf("\n[SUCCESS] Authentication successful!\n");
                if(selectedOption == LOGIN_TYPE.IT_ACCOUNT) {
                    handleMainMenu_ITAccount(db, username, selectedOption);
                }
                else if(selectedOption == LOGIN_TYPE.EID_ACCOUNT) {
                    handleMainMenu_EIdAccount(db, eid, selectedOption);
                }
                else {
                    handleMainMenu_AdminAccount(db, username, selectedOption);
                }
                break;  // Exit authentication loop after successful login and menu handling
            } else {
                printf("\n[ERROR] Authentication failed! Attempts remaining: %d\n", 
                       MAX_INPUT_ATTEMPTS - loginAttempts - 1);
                loginAttempts++;
            }
        }

        if (!authenticated) {
            printf("\n[ERROR] Maximum authentication attempts reached.\n");
            sqlite3_close(db);
            return 1;
        }

        clearScreen();
    }

    sqlite3_close(db);
    return 0;
}