## Starting for the first time

- Create .env file from .env.template. Change the variables accordingly.
- Create database.json from database.json.template.

## Some Helpful Scripts

- Generate Documentation: <em>npm run-script generateDocs</em>
- To run test: <em>npm test</em>

# Checklists

### Adding/Updating Existing API

- Update the API documentation.
- Export postman collection in ./tests/MLM.postman_collection.json file.
- Generate new documentation with command: <em>npm run-script generateDocs</em>

# Documenting API

### Generate API Documentation

<em>npm run-script generateDocs</em>

### View API Documentation

- Run: npm start or nodemon start
- API documentation is served through a route http://localhost:5200/docs. Code is present in app.js

### Updating API Documentation

- Copy the existing documentation comment (/\*_ ... _/) to \_apidoc.js.
- Update the route documentation.
- Increment @apiVersion of the route and add same version in apidoc.json.

### Write New API Documentation

- Use following template:

<pre>
/**
 * @api {get} /route/path/:parameter <NavigatonPanel: sample title max 3-4 words>
 * @apiVersion 1.0.1
 * @apiGroup <GroupName: UsedInNavigatonPanel>
 * @apiName <NavigationSubMenu: NameOfAPI3-4Words>
 * @apiDescription <Descprition can span multiple lines>
 * @apiPermission <admin|retailer|all|none> <SomeDescription>
 *
 * @apiHeader <{String|Number|Boolean|Object|String[]}> <fieldName> <Description>
 *  [field]: Optional Header field
 *  [field=defaultValue]: defaultValue for header
 *
 * @apiParam <{String|Number|Boolean|Object|String[]}> <fieldName> <Description>
 * {type}: {String} : String Type.
 *          {String{..5}}: String with max 5 characters
 *          {String{2..5}}: String with minimum of 2 maximum of 5 characters
 *          {number{100-999}}: Number between 100 and 999
 *          {String="small","huge"}: These two words allowed
 *          {Number=1,23,65}: Only number 1,23,65 allowed
 *          {String{..5}="small","huge"}: String with max 5 characters and only contains the word "small" or "huge"
 * [field]: Optional Field
 * field[nestedField]: Mandatory nested field. For example address[street], address[city].
 *                      Here address is object address : { street: , city: }
 * field=defaultValue: Like sortBy=name
 *
 * (Only for POST/PUT/DELETE)
 * @apiParamExample {json} <ExampleName>
 *        {
 *          "id": 4711
 *        }
 *
 * @apiSuccessExample {json} <SuccessTitle>
 *     HTTP/1.1 200 OK
 *     {
 *       "firstname": "John",
 *       "lastname": "Doe"
 *     }
 *
 * @apiErrorExample {json} <ErrorName>
 *     HTTP/1.1 404 Not Found
 *     {
 *       "error": "UserNotFound"
 *     }
 *
 * @apiErrorExample {json} Validation Error
 *     HTTP/1.1 400 Bad Request
 *     {
 *       "error": "UserNotFound"
 *     }
 */
</pre>

# Development Related

For more details read <em>./tests/README.md</em>

# Database Migrations

We are using <em>db-migrate</em> module for database migrations. This package creates <em>migrations</em> table in database to track migration we ran till now. When we create a migrations using <em>db-migrate</em> it create <Project_root>/migrations folder where it add migration scripts (We mostly use sql migrations to avoid full dependency on db-migrate). It also needs database.json file to make connection to database for running migration(s). We mainly have three types of migrations:

### Schema related migrations:

These are present directly under <project_root>/migrations. We have to run these migrations before any other types of migrations runs.

- To create: db-migrate create <migration_name>
- To run: "db-migrate up" or "db-migate down"

### Data related migrations:

These are present in <project_root>/migrations/data folder. We run these migrations after we run all schema related migrations. These mostly contain data that needed to be present in production and development environment. This data is basic need for application to work correctly. For example, list of cities, list of notification status (new, read, unread) etc.

- To create: db-migrate create:data <migration_name>
- To run: "db-migrate up:data" or "db-migrate down:data"

### Tests related migration

These are present in <project_root>/migrations/tests folder. We run these migrations after we run all schema related migrations and data related migrations. These contains the data this is not basic need for an application to work correctly. This data is a dummy data that we will only use for testing. For example, list of enquiries, list of payment requests etc.

- To create: db-migrate create:tests <migration_name>
- To run: "db-migrate up:tests" or "db-migrate down:tests"

### List of migrations we need depending on scenario

- Production/Staging: Schema Related migrations + Data Related migrations
- Development: Schema Related migrations + Data Related migrations + (Optional: Test Related Migration)
- Testing: Schema Related migrations + Data Related migrations + Test Related Migration

# .env File Content

### Miscellaneous

- NODE_ENV: (development|production|testing|staging) Your application environment.
- AUTH_JWT_SECRET: Secret used for encoding JWT tokens.
- PORT: Port application should run on.

### Logging related

- LOG_LEVEL: (error|warn|info|http|verbose|debug|silly) The log level selected for logging. If you select a level then all levels below it will also be logged. For example if log level is info then error and warn will be also be logged however http, verbose, debug and silly will not be logged.
- LOG_TO_CONSOLE: (true|false) Whether you want to log the output on console or not. true will log on console also along with a log file in "./log" dir. For production it should be always false, we only use this in case of development for looking at console instead of opening log files.
- LOG_HANDLE_EXCEPTION: (true|false) Whether logger should handle the uncaught exception. If specified as true then logger will log the errors.
  - [IMP] Sometime logger will not report the exact location of the errors like file name and line number. In that case its better to let node enviroment to handle crash and report it. Hence for such debugging make it false and check to see the cause.
- LOG_HANDLE_REJECTION: (true|false) Whether logger should handle the uncaught exception.
- LOG_INCOMING_REQUEST: (true|false) Whether logger should log the incoming requests or not. This currently uses the morgan for logging but issue with morgan is that it does not have time stamp associated with requests and it logs the requests when resonse gets sent but we need some way to log before request gets processed. When we will implement that in future we will use this variable.

### Database Related

- DB_HOST: Host on which DB server is running.
- DB_USER: User name for Database.
- DB_PASSWORD: Password of the user.
- DB_DATABASE_NAME: Database name.

### Email Sender Configuration

- EMAIL_BASE_LINK: When we generate URL which we sent in email. That URL bases in specified.
- NODEMAILER_HOST: Hostname/IP of your email server.
- NODEMAILER_PORT: Port on which email server is running.
- NODEMAILER_EMAIL: Which account to use to send email. This can be sengrid account also.
- NODEMAILER_PASSWORD: Password for the email account from which we are sending the email.
- NODEMAILER_FROM: From email to be displayed to receiver. This can be different from NODEMAILER_EMAIL.

### Minimal .env file example

<pre>
#####################################
# Mandatory For Every Environment
#####################################
NODE_ENV = development
AUTH_JWT_SECRET = MyTempSecret
# Logging related
LOG_LEVEL = info
LOG_TO_CONSOLE = true
LOG_HANDLE_EXCEPTION = true
LOG_HANDLE_REJECTION = true

#####################################
# Optional
#####################################

</pre>

# Testing Application

For more details read <em>./tests/README.md</em>

# Scripts

### tools\scripts\recreate-dev-db.bat

When to use:

- When you want to freshly install DB with new changes.
- When your DB state has changed while testing your development stuff and you want to restore it to original consistent state.

REQUIREMENTS: mysql.exe should be in PATH variable. Also you need db-migration npm module to be installed globally.

CAUTION:

- Use this only in windows command prompt, not in powershell.
- Not to be used in production

How to use it?

- When prompted provide root users password.

```
> cd tools\scripts
> recreate-db.bat
"Creating New Database..."
Enter password:
"Importing Schema by running migrations..."
received data: CREATE TABLE `employee`
...<Some migration SQL statements>...
[INFO] Processed migration <migration_name>
[INFO] Done
"Successfully recreated database"
```

### tools\scripts\dump-db.bat

When to use:

- This script has been obselete and not needed so don't use it.
- You can uncomment line and use it just for looking into DB sqls and nothing more.
- You should not update it or push the sql files generated by un-commenting it.

# Miscellaneous

## How to start contributing for the first time?

You need to clone the directory and then execute following commands

1. <em>git checkout -b dev origin/dev</em> (This creates local git developer branch which points to remote's 'dev' branch.
2. Do changes and commit it.
3. <em>git push</em>: This will push your changes into remote's dev branch.
