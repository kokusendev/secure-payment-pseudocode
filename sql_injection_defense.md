# SQL Injection Defense - Parameterized Queries

SQL injection occurs when user input is concatenated directly into a query 
string, allowing an attacker to alter the structure of the query itself. 
The defense is to use parameterized queries that bind user input as a data 
value rather than inserting it into the query string directly.

## Parameterized Query Pseudocode

```
// SQL INJECTION DEFENSE
// Parameterized queries prevent user input from altering query structure

FUNCTION executeSecurePaymentQuery(sanitizedInput):

    // VULNERABLE approach - never do this
    // query = "SELECT balance FROM accounts WHERE id = " + sanitizedInput.accountId
    // raw concatenation allows an attacker to inject SQL syntax

    // SECURE approach - parameterized query
    // user input is bound as a value, not inserted into the query string
    query = "SELECT balance FROM accounts WHERE account_id = ?"

    // prepare the statement before binding any parameters
    preparedStatement = database.prepare(query)

    // bind sanitized input as a parameter
    // the database treats this as a data value, not executable SQL
    preparedStatement.bind(sanitizedInput.accountId)

    // execute using least privilege database account
    // payment processor has SELECT only, no DROP or DELETE access
    result = preparedStatement.execute()

    // validate result format before returning
    IF result is null THEN
        log suspicious query attempt with input details
        return null
    END IF

    IF result format does not match expected schema THEN
        log unexpected result structure
        return null
    END IF

    return result

END FUNCTION
```

## Why This Works

The parameterized query approach binds user input as a data value rather than 
inserting it directly into the query string. An attacker entering 
`' OR '1'='1` into the account ID field cannot alter the query structure 
because the input is never treated as SQL syntax. The least privilege database 
account adds a secondary layer of defense by ensuring that even if an injection 
were somehow successful, the attacker's ability to cause damage is limited by 
the permissions of the account executing the query.
