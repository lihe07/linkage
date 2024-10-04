test_static:
	cd bin && make static
	cargo r ./bin/static

test_example:
	cd bin && make example
	cargo r ./bin/example

