# Makefile for managing TITAN container environment

up:
	docker-compose up -d

down:
	docker-compose down

rebuild:
	docker-compose down --volumes
	docker-compose build
	docker-compose up -d

logs:
	docker-compose logs -f

shell:
	docker exec -it titan bash

timesketch-shell:
	docker exec -it timesketch bash