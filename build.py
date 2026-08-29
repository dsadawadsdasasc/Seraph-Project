# FILE: build.py
import os, random, subprocess
def main():
    random_id = random.randint(0, 0xFFFFFFFF)
    svcname = f"{random_id:08X}"
    owner_id = "YOUR_OWNER_ID_HERE"
    print(f"Building with service name: {svcname}")
    driver_cmd = ["cl", "/nologo", "/W4", "/WX", "/O2", "/D", "_KERNEL_MODE", "/D", f"SVCNAME=L\"{svcname}\"", "/kernel", "driver.c", "evasion_kernel.c", "/link", "/driver", "/out:shadowpfn.sys", "bcrypt.lib"]
    subprocess.run(driver_cmd, check=True)
    os.rename("shadowpfn.sys", f"{svcname}.sys")
    with open("driver.rc", "w") as f:
        f.write('#include "resource.h"\n')
        f.write(f'IDR_DRIVER RCDATA "{svcname}.sys"\n')
    subprocess.run(["rc", "/fo", "driver.res", "driver.rc"], check=True)
    loader_objs = []
    for src in ["loader.c", "evasion_user.c", "checks.c", "command.c", "keyauth.c", "gui.c", "gui_core.cpp", "Overlay.cpp"]:
        obj = src.replace(".c", ".obj").replace(".cpp", ".obj")
        subprocess.run(["cl", "/nologo", "/W4", "/O2", "/c", "/D", f"SVCNAME=L\"{svcname}\"", "/D", f"OWNER_ID=L\"{owner_id}\"", src], check=True)
        loader_objs.append(obj)
    link_cmd = ["link", "/nologo", "/OUT:loader.exe"] + loader_objs + ["driver.res", "user32.lib", "advapi32.lib", "bcrypt.lib", "ntdll.lib", "winhttp.lib", "d3d12.lib", "dxgi.lib", "d3dcompiler.lib"]
    subprocess.run(link_cmd, check=True)
    for f in ["driver.rc", "driver.res", f"{svcname}.sys"] + loader_objs:
        if os.path.exists(f):
            os.remove(f)
    print("Build completed. Output: loader.exe")
if __name__ == "__main__":
    main()