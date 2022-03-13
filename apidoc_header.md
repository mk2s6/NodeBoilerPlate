## Details of Error object returned by backend
- The error object will be of form:
<pre> 400 Bad Request: Invalid Username and Password.
{
    "type": 0|1|2|3,
    "code": <Some Number>,
    "message": "<Detailed Error message>",
    "errors": [
        {
            "message": "Please enter valid email",
            "field": "ui_email",
            "location": "body"
        },
        {
            "message": "Password should have at least 8 characters",
            "field": "ui_password",
            "location": "body"
        }
]
}
</pre>
- type: This return the type of error reported. (See below table for details)
- code: Integer code given by backend. This you need to report to backend which will help us trace the error cause.
- message: Readable rrror message returned by backend. This can be displayed directly to user in a pop up.
- error[]: This will be provided only in case of validation errors. This will contain list of parameters for which validation failed and message. You can display message alongside the input based on field.

## Types of Error retruned by routes
| Error Type            | Type code | Remark                                                                                                                                            |
|-----------------------|-----------|---------------------------------------------------------------------------------------------------------------------------------------------------|
| Validation Error      | 0         | Returned on input validation failure with status code of 422.<br>UI should show their custom error messages alongside appropriate field.          |
| Internal Server Error | 1         | Returned when there is issue on server side and we can't process the request.<br>UI should show a popup of this error and tell user to try again. |
| Database Errors       | 2         | Returned when error is associated to data in database.<br>UI should show a popup of this error and tell user to try again.                        |
| Authentication Error  | 3         | These are the error when user is not authorized to use this.<br>UI should clear the token stored and redirect to login page.                      |

## Default Test Login credentials
Username: 
Password: 