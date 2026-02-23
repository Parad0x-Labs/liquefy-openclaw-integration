CREATE TABLE users(id INT PRIMARY KEY, name TEXT, email TEXT);
INSERT INTO users VALUES (1,'alice','alice@example.com');
INSERT INTO users VALUES (2,'bob','bob@example.com');
INSERT INTO users VALUES (3,'charlie','charlie@example.com');
SELECT * FROM users WHERE id = 1;
