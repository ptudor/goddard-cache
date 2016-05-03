NAME="x"
TAG="latest"

build:
	@docker build .

sh:
	@docker exec -it ${} sh
