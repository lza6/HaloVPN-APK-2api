import frida, time
dev = frida.get_usb_device(timeout=10)
ADB_APP = "com.thehot.halovpnpro"
sess = dev.attach(ADB_APP)
print("attached", flush=True)
src = open("hook_key.js", encoding="utf-8").read()
sc = sess.create_script(src)
sc.on("message", lambda m, d: print(m, flush=True))
sc.load()
print("loaded", flush=True)
time.sleep(60)
