# Cross-Site Scripting Defense - Input Sanitization and Output Encoding

Cross-site scripting occurs when an attacker injects malicious scripts into 
web content that other users then execute in their browsers. The defense 
operates at two points in the payment flow: input sanitization catches 
dangerous content before it enters the system, and output encoding ensures 
anything rendered back to the browser is treated as text rather than 
executable code.

## Input Sanitization Pseudocode

```
// XSS DEFENSE - INPUT SANITIZATION
// Strip or encode dangerous characters before any processing occurs

FUNCTION sanitizeInput(rawInput):

    // reject null or empty input immediately
    IF rawInput is null OR rawInput is empty THEN
        return null
    END IF

    // enforce maximum input length
    // prevents buffer overflow and limits attack string length
    IF length of rawInput exceeds maximumAllowedLength THEN
        log oversized input attempt
        return null
    END IF

    // scan for known script injection patterns
    IF rawInput contains any of the following THEN
        "<script>"
        "</script>"
        "javascript:"
        "onerror="
        "onload="
        "eval("
        log injection attempt with timestamp and input value
        return null
    END IF

    // encode dangerous HTML characters
    // converts characters that have special meaning in HTML
    // to their safe entity equivalents
    FOR each character in rawInput:
        IF character = "<"  THEN replace with "&lt;"
        IF character = ">"  THEN replace with "&gt;"
        IF character = '"'  THEN replace with "&quot;"
        IF character = "'"  THEN replace with "&#x27;"
        IF character = "/"  THEN replace with "&#x2F;"
        IF character = "&"  THEN replace with "&amp;"
    END FOR

    return sanitizedInput

END FUNCTION
```

## Output Encoding Pseudocode

```
// XSS DEFENSE - OUTPUT ENCODING
// Encode all data before rendering it to the browser

FUNCTION encodeOutput(result):

    // encode every field in the result before display
    // data stored in the database may contain characters
    // that were not caught at input time
    FOR each field in result:
        field = htmlEncode(field)
    END FOR

    // set Content Security Policy header
    // restricts which scripts the browser is allowed to execute
    // blocks inline scripts and scripts from untrusted sources
    setResponseHeader("Content-Security-Policy", "default-src 'self'")

    // set XSS protection header for older browsers
    setResponseHeader("X-XSS-Protection", "1; mode=block")

    // set header to prevent MIME type sniffing
    setResponseHeader("X-Content-Type-Options", "nosniff")

    return encodedResult

END FUNCTION
```

## Why This Works

The XSS defense operates at two points in the payment flow. Input sanitization 
catches and removes dangerous content before it enters the system. Output 
encoding ensures that anything rendered back to the browser is treated as text 
rather than executable code by converting characters like `<` and `>` to their 
HTML entity equivalents. The Content Security Policy header adds a third layer 
by instructing the browser itself to reject scripts from untrusted sources even 
if malicious content somehow makes it through sanitization and encoding.
