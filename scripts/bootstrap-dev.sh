#!/bin/bash
docker-compose -f "docker-compose.yml" --env-file .env.dev up -d