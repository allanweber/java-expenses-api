# Expense API

# Running the project locally

* Local profile
```
SPRING_PROFILES_ACTIVE=local
```
* Postgres docker container
```bash
docker run --name expense-postgres -e POSTGRES_PASSWORD=expense -e POSTGRES_USER=expense -e POSTGRES_DB=expense -p 5432:5432 -d postgres
```

* Generate a secret private key for JWT
```bash
openssl rand -base64 32
```

http://localhost:8080/swagger-ui/index.html