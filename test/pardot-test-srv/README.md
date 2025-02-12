# pardot-test-srv

`pardot-test-srv` is a lightweight mock server for integration testing with the Salesforce Pardot API and OAuth authentication.

## Features

- Simulates Salesforce OAuth2 authentication with configurable credentials.
- Issues randomly generated Bearer tokens for API authentication.
- Provides a mock Pardot API that validates Bearer tokens and requires a business unit header.
- Exposes an endpoint to query submitted emails by business unit (in development mode).
- Allows forced Bearer token expiration for testing authentication flows (in development mode).

## Usage

Run `pardot-test-srv` with a configuration file:
```sh
go run test/partdot-test-srv/main.go <config.json>
```

### Example Configuration (`config.json`)

```json
{
  "oAuthPort": 8080,
  "pardotPort": 9090,
  "expectedClientID": "my-client-id",
  "expectedClientSecret": "my-client-secret",
  "developmentMode": false
}
```

## API Endpoints

### OAuth Token Request

**Endpoint:** `POST /services/oauth2/token`  
**Parameters (Form Data):**  
- `client_id`
- `client_secret`

**Response:**
```json
{
  "access_token": "randomly-generated-token",
  "token_type": "Bearer",
  "expires_in": "3600"
}
```

### Create Prospect

**Endpoint:** `POST /api/v5/objects/prospects`  
**Headers:**
- `Authorization: Bearer <token>`
- `Pardot-Business-Unit-Id: <business_unit>`

**Payload Example:**
```json
{
  "email": "email@example.com"
}
```

**Response:**
```json
{
  "status": "success"
}
```

### Query Submitted Prospects (Development Mode Only)

**Endpoint:** `GET /query_prospects`  
**Query Parameter:**  
- `pardot_business_unit_id=<business_unit>`

**Response:**
```json
{
  "prospects": [
    "email1@example.com",
    "email2@example.com"
  ]
}
```

### Force Token Expiration (Development Mode Only)

**Endpoint:** `GET /expire_token`  

**Response:**
```json
{
  "status": "token expired"
}
```