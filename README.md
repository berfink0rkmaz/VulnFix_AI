# VulnFix AI - AI-Powered Security Vulnerability Analysis

VulnFix AI is a next-generation, AI-powered service designed to find security vulnerabilities in code and suggest automatic fixes using Google Gemini 1.5 Flash AI. This service transforms security testing from an afterthought into an integral part of the development process.

## 🚀 Features

- **AI-Powered Vulnerability Detection**: Uses Google Gemini 1.5 Flash to analyze code for security vulnerabilities
- **Automatic Code Fixes**: Generates secure code suggestions for detected vulnerabilities
- **Multi-Language Support**: Analyzes code in various programming languages
- **Real-time Analysis**: Asynchronous processing with status tracking
- **Comprehensive Reporting**: Detailed vulnerability reports with severity levels and CWE mappings
- **RESTful API**: Clean, well-documented API with Swagger/OpenAPI support
- **JWT Authentication**: Secure token-based authentication
- **User Management**: User registration, login, and role-based access control
- **Statistics & Analytics**: Track vulnerability trends and analysis metrics

## 🏗️ Architecture

The project follows a clean layered architecture:

```
┌─────────────────┐
│   Controllers   │  ← REST API endpoints
├─────────────────┤
│    Services     │  ← Business logic
├─────────────────┤
│  Repositories   │  ← Data access layer
├─────────────────┤
│    Entities     │  ← Data models
└─────────────────┘
```

## 🛠️ Technology Stack

- **Backend**: Spring Boot 3.3.3 (Java 17)
- **Database**: PostgreSQL
- **AI Integration**: Google Gemini 1.5 Flash API
- **Authentication**: JWT (JSON Web Tokens)
- **Documentation**: Swagger/OpenAPI 3
- **Build Tool**: Maven
- **Security**: Spring Security
- **Validation**: Bean Validation (JSR-303)
- **Logging**: SLF4J with Logback

## 📋 Prerequisites

- Java 17 or higher
- Maven 3.6+
- PostgreSQL 12+
- Google Gemini API key

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone <repository-url>
cd VulnFix_AI
```

### 2. Database Setup

Create a PostgreSQL database:

```sql
CREATE DATABASE vulnfix_ai;
CREATE USER vulnfix_user WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE vulnfix_ai TO vulnfix_user;
```

### 3. Configuration

Update `src/main/resources/application.properties`:

```properties
# Database Configuration
spring.datasource.url=jdbc:postgresql://localhost:5432/vulnfix_ai
spring.datasource.username=vulnfix_user
spring.datasource.password=your_password

# Google Gemini AI Configuration
gemini.api.key=your-gemini-api-key-here

# JWT Configuration
jwt.secret=your-super-secret-jwt-key-here
```

### 4. Build and Run

```bash
# Build the project
mvn clean install

# Run the application
mvn spring-boot:run
```

The application will start on `http://localhost:8080`

### 5. Access the API Documentation

- Swagger UI: `http://localhost:8080/api/v1/swagger-ui.html`
- OpenAPI JSON: `http://localhost:8080/api/v1/api-docs`

## 📚 API Usage

### Authentication

1. **Register a new user**:
```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "developer",
    "email": "dev@example.com",
    "password": "password123",
    "firstName": "John",
    "lastName": "Doe"
  }'
```

2. **Login to get JWT token**:
```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "developer",
    "password": "password123"
  }'
```

### Code Analysis

3. **Analyze code for vulnerabilities**:
```bash
curl -X POST http://localhost:8080/api/v1/analysis \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{
    "sourceCode": "String query = \"SELECT * FROM users WHERE id = \" + userId;",
    "programmingLanguage": "java",
    "analysisType": "SECURITY_VULNERABILITIES",
    "projectContext": "Web application with user management"
  }'
```

4. **Get analysis results**:
```bash
curl -X GET http://localhost:8080/api/v1/analysis/1 \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

5. **Generate code fix for vulnerability**:
```bash
curl -X GET http://localhost:8080/api/v1/analysis/1/vulnerabilities/1/fix \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

## 🔧 Configuration Options

### Environment Variables

- `GEMINI_API_KEY`: Your Google Gemini API key
- `JWT_SECRET`: Secret key for JWT token signing
- `DB_URL`: Database connection URL
- `DB_USERNAME`: Database username
- `DB_PASSWORD`: Database password

### Application Properties

Key configuration options in `application.properties`:

```properties
# Server Configuration
server.port=8080
server.servlet.context-path=/api/v1

# Database Configuration
spring.jpa.hibernate.ddl-auto=update
spring.jpa.show-sql=true

# AI Configuration
gemini.api.url=https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent

# JWT Configuration
jwt.expiration=86400000

# Logging Configuration
logging.level.org.example.vulnfix_ai=DEBUG
```

## 🧪 Testing

### Unit Tests

```bash
mvn test
```

### Integration Tests

```bash
mvn verify
```

### Manual Testing

Use the Swagger UI at `http://localhost:8080/api/v1/swagger-ui.html` to test the API endpoints interactively.

## 📊 Database Schema

The application uses the following main entities:

- **Users**: User accounts and authentication
- **CodeAnalysis**: Analysis requests and results
- **Vulnerabilities**: Detected security vulnerabilities

## 🔒 Security Features

- JWT-based authentication
- Password encryption with BCrypt
- Role-based access control
- Input validation and sanitization
- CORS configuration
- Global exception handling

## 🚀 Deployment

### Docker Deployment

1. Build the Docker image:
```bash
docker build -t vulnfix-ai .
```

2. Run the container:
```bash
docker run -p 8080:8080 \
  -e GEMINI_API_KEY=your-key \
  -e DB_URL=jdbc:postgresql://db:5432/vulnfix_ai \
  vulnfix-ai
```

### Production Deployment

1. Set environment variables for production
2. Configure a production database
3. Set up SSL/TLS certificates
4. Configure logging and monitoring
5. Set up backup and recovery procedures

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: Check the Swagger UI for detailed API documentation
- **Issues**: Report bugs and feature requests via GitHub Issues
- **Email**: support@vulnfix.ai

## 🔮 Roadmap

- [ ] Support for more programming languages
- [ ] Integration with CI/CD pipelines
- [ ] Real-time vulnerability monitoring
- [ ] Advanced code analysis features
- [ ] Team collaboration features
- [ ] Custom vulnerability rules
- [ ] Performance optimization
- [ ] Mobile application

---

**VulnFix AI** - Making software security accessible and automated through AI. 