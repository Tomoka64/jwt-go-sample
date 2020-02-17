run:
	docker-compose build --no-cache && docker-compose up

stop:
	docker-compose down