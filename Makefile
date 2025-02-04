ANDROID_NDK_HOME=$(HOME)/Android/Sdk/ndk/27.0.12077973/
export ANDROID_NDK_HOME

linkage:
	cargo ndk -t arm64-v8a b
	cp ./target/aarch64-linux-android/debug/linkage ./qiling
	cp ./target/aarch64-linux-android/debug/liblinkage.so .

qiling: linkage
	cp ~/Documents/krf/target/lib/arm64-v8a/libil2cpp.so ./qiling/arm64_android6.0/libil2cpp.so
	cd ./qiling && python ./main.py

apk: linkage
	cp ./liblinkage.so ~/Documents/krf/target/lib/arm64-v8a/
	# Create apk using zip
	apktool b ~/Documents/krf/target/ -o ./target.apk
	# Sign it with uber-apk-signer
	uber-apk-signer -a ./target.apk
	rm target.apk target-aligned-debugSigned.apk.idsig
	mv target-aligned-debugSigned.apk target.apk

