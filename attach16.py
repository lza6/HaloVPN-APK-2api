import frida, time, sys
dev = frida.get_usb_device(timeout=10)
app = "com.thehot.halovpnpro"
sess = dev.attach(app)
print("attached", flush=True)
sc = sess.create_script(open("hook_params.js", encoding="utf-8").read())
sc.on("message", lambda m, d: print(m, flush=True))
sc.load()
print("loaded", flush=True)
time.sleep(int(sys.argv[1]) if len(sys.argv) > 1 else 60)
