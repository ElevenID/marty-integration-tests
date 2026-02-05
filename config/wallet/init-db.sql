-- Initialize Walt.id database
-- This script runs automatically when the waltid-postgres container first starts

-- Create the waltid database if it doesn't exist
SELECT 'CREATE DATABASE waltid'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'waltid')\gexec

-- Grant all privileges to the waltid user
GRANT ALL PRIVILEGES ON DATABASE waltid TO waltid;
