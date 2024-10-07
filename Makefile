test_static:
	cd bin && make static
	cargo r ./bin/static

test_example:
	cd bin && make example
	cargo r ./bin/example

ANDROID_NDK_HOME=/opt/android-ndk/
export ANDROID_NDK_HOME

linkage:
	cargo ndk -t arm64-v8a b
	cp ./target/aarch64-linux-android/debug/linkage ./qiling
	cp ./target/aarch64-linux-android/debug/liblinkage.so ~/Documents/krf/target/lib/arm64-v8a/

qiling: linkage
	cd ./qiling && python ./main.py
