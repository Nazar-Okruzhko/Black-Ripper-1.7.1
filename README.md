# Project NinjaRipper: Reborn - Black Exploit

# W.I.P. => Project is under a lot of the digging....

### Original NinjaRipper 1.7.1 Source Folder:

<img width="718" height="451" alt="Screenshot (3289)" src="https://github.com/user-attachments/assets/1ab20d10-4b3d-467f-a9af-5163ed987554" />

### Original NinjaRipper 1.7.1 Structure:
      └── NinjaRipperSrc_x64/
          ├── intruder/
          │   ├── intruder.aps
          │   ├── intruder.cpp
          │   ├── intruder.def
          │   ├── intruder.h
          │   ├── intruder.log
          │   ├── intruder.rc
          │   ├── intruder.sln
          │   ├── intruder.suo
          │   ├── intruder.v12.suo
          │   ├── intruder.vcproj
          │   ├── intruder.vcxproj
          │   ├── intruder.vcxproj.filters
          │   ├── intruder.vcxproj.user
          │   ├── intruder1.aps
          │   ├── intruder1.rc
          │   ├── intruder1.res
          │   ├── process.cpp
          │   ├── process.h
          │   ├── ReadMe.txt
          │   ├── resource.h
          │   ├── resource1.h
          │   ├── MinHook/
          │   │   ├── .editorconfig
          │   │   ├── AUTHORS.txt
          │   │   ├── LICENSE.txt
          │   │   ├── src/
          │   │   │   ├── buffer.c
          │   │   │   ├── buffer.h
          │   │   │   ├── hook.c
          │   │   │   ├── trampoline.c
          │   │   │   ├── trampoline.h
          │   │   │   └── HDE/
          │   │   │       ├── hde32.c
          │   │   │       ├── hde32.h
          │   │   │       ├── hde64.c
          │   │   │       ├── hde64.h
          │   │   │       ├── pstdint.h
          │   │   │       ├── table32.h
          │   │   │       └── table64.h
          │   │   ├── include/
          │   │   │   └── MinHook.h
          │   │   ├── dll_resources/
          │   │   │   ├── MinHook.def
          │   │   │   └── MinHook.rc
          │   │   └── build/
          │   │       ├── VC9/
          │   │       │   ├── libMinHook.vcproj
          │   │       │   ├── MinHook.vcproj
          │   │       │   └── MinHookVC9.sln
          │   │       ├── VC12/
          │   │       │   ├── libMinHook.vcxproj
          │   │       │   ├── libMinHook.vcxproj.filters
          │   │       │   ├── MinHook.vcxproj
          │   │       │   ├── MinHookVC12.sln
          │   │       │   ├── MinHookVC12.v12.suo
          │   │       │   ├── lib/
          │   │       │   │   ├── Release/
          │   │       │   │   │   ├── libMinHook.x64.lib
          │   │       │   │   │   └── libMinHook.x86.lib
          │   │       │   │   └── Debug/
          │   │       │   │       ├── libMinHook.x64.lib
          │   │       │   │       └── libMinHook.x86.lib
          │   │       │   └── bin/
          │   │       │       ├── Release/
          │   │       │       │   ├── MinHook.x64.dll
          │   │       │       │   ├── MinHook.x64.exp
          │   │       │       │   ├── MinHook.x64.lib
          │   │       │       │   ├── MinHook.x86.dll
          │   │       │       │   ├── MinHook.x86.exp
          │   │       │       │   └── MinHook.x86.lib
          │   │       │       └── Debug/
          │   │       │           ├── MinHook.x64.dll
          │   │       │           ├── MinHook.x64.exp
          │   │       │           ├── MinHook.x64.ilk
          │   │       │           ├── MinHook.x64.lib
          │   │       │           ├── MinHook.x86.dll
          │   │       │           ├── MinHook.x86.exp
          │   │       │           ├── MinHook.x86.ilk
          │   │       │           └── MinHook.x86.lib
          │   │       ├── VC11/
          │   │       │   ├── libMinHook.vcxproj
          │   │       │   ├── libMinHook.vcxproj.filters
          │   │       │   ├── MinHook.vcxproj
          │   │       │   └── MinHookVC11.sln
          │   │       └── VC10/
          │   │           ├── libMinHook.vcxproj
          │   │           ├── libMinHook.vcxproj.filters
          │   │           ├── libMinHook.vcxproj.user
          │   │           ├── MinHook.vcxproj
          │   │           ├── MinHook.vcxproj.user
          │   │           ├── MinHookVC10.sln
          │   │           └── MinHookVC10.suo
          │   ├── dxgi/
          │   │   ├── dxgitypes.h
          │   │   ├── enums.h
          │   │   ├── kdxgi.cpp
          │   │   ├── kdxgi.h
          │   │   ├── macrodxgi.h
          │   │   ├── predxgi.cpp
          │   │   └── predxgi.h
          │   ├── dx9/
          │   │   ├── drawindexedprimitive9.cpp
          │   │   ├── drawindexedprimitiveup9.cpp
          │   │   ├── drawprimitive9.cpp
          │   │   ├── drawprimitiveup9.cpp
          │   │   ├── dump9.cpp
          │   │   ├── dx9types.h
          │   │   ├── enums.h
          │   │   ├── kripper9.cpp
          │   │   ├── kripper9.h
          │   │   ├── macro.h
          │   │   ├── pre9.cpp
          │   │   ├── pre9.h
          │   │   ├── savemeshtextures9.cpp
          │   │   ├── saveshader9.cpp
          │   │   ├── savetexture9.cpp
          │   │   └── texture9.cpp
          │   ├── dx8/
          │   │   ├── drawindexedprimitive8.cpp
          │   │   ├── drawindexedprimitiveup8.cpp
          │   │   ├── drawprimitive8.cpp
          │   │   ├── drawprimitiveup8.cpp
          │   │   ├── dump8.cpp
          │   │   ├── dx8types.h
          │   │   ├── enums.h
          │   │   ├── kripper8.cpp
          │   │   ├── kripper8.h
          │   │   ├── pre8.cpp
          │   │   ├── pre8.h
          │   │   ├── savemeshtextures8.cpp
          │   │   ├── sm1_disasm.cpp
          │   │   ├── sm1_disasm.h
          │   │   ├── sm1_vertdecl.cpp
          │   │   ├── sm1_vertdecl.h
          │   │   └── texture8.cpp
          │   ├── dx7/
          │   │   ├── drawindexedprimitive7.cpp
          │   │   ├── drawindexedprimitivestrided7.cpp
          │   │   ├── drawindexedprimitivevb7.cpp
          │   │   ├── drawprimitive7.cpp
          │   │   ├── drawprimitivestrided7.cpp
          │   │   ├── drawprimitivevb7.cpp
          │   │   ├── dx7types.h
          │   │   ├── enums.h
          │   │   ├── kripper7.cpp
          │   │   ├── kripper7.h
          │   │   ├── macro.h
          │   │   ├── pre7.cpp
          │   │   ├── pre7.h
          │   │   ├── savemeshtextures7.cpp
          │   │   ├── savetexture7.cpp
          │   │   └── texture7.cpp
          │   ├── dx6/
          │   │   ├── drawindexedprimitive6.cpp
          │   │   ├── drawindexedprimitivestrided6.cpp
          │   │   ├── drawindexedprimitivevb6.cpp
          │   │   ├── drawprimitive6.cpp
          │   │   ├── drawprimitivestrided6.cpp
          │   │   ├── drawprimitivevb6.cpp
          │   │   ├── dx6types.h
          │   │   ├── enums.h
          │   │   ├── kripper6.cpp
          │   │   ├── kripper6.h
          │   │   ├── macro.h
          │   │   ├── pre6.cpp
          │   │   ├── pre6.h
          │   │   ├── savemeshtextures6.cpp
          │   │   ├── savetexture6.cpp
          │   │   └── texture6.cpp
          │   ├── dx11/
          │   │   ├── draw11.cpp
          │   │   ├── drawauto11.cpp
          │   │   ├── drawindexed11.cpp
          │   │   ├── drawindexedinstanced11.cpp
          │   │   ├── drawindexedinstancedindirect11.cpp
          │   │   ├── drawinstanced11.cpp
          │   │   ├── drawinstancedindirect11.cpp
          │   │   ├── dump11.cpp
          │   │   ├── dx11types.h
          │   │   ├── enums.h
          │   │   ├── guiddump.h
          │   │   ├── kripper11.cpp
          │   │   ├── kripper11.h
          │   │   ├── macro.h
          │   │   ├── pre11.cpp
          │   │   ├── pre11.h
          │   │   ├── savemeshtextures11.cpp
          │   │   ├── savetexture11.cpp
          │   │   └── texture11.cpp
          │   ├── DirectXTex/
          │   │   ├── .gitignore
          │   │   ├── DirectXTex_Desktop_2012.sln
          │   │   ├── DirectXTex_Desktop_2013.sln
          │   │   ├── DirectXTex_Desktop_2013.v12.suo
          │   │   ├── DirectXTex_Desktop_2015.sln
          │   │   ├── DirectXTex_Windows10.sln
          │   │   ├── DirectXTex_Windows81.sln
          │   │   ├── DirectXTex_WindowsPhone81.sln
          │   │   ├── DirectXTex_XboxOneADK.sln
          │   │   ├── DirectXTex_XboxOneXDK.sln
          │   │   ├── DirectXTex_XboxOneXDK_2015.sln
          │   │   ├── MIT.txt
          │   │   ├── ReadMe.txt
          │   │   ├── WICTextureLoader/
          │   │   │   ├── WICTextureLoader.cpp
          │   │   │   └── WICTextureLoader.h
          │   │   ├── Texconv/
          │   │   │   ├── directx.ico
          │   │   │   ├── texconv.cpp
          │   │   │   ├── Texconv.rc
          │   │   │   ├── Texconv_Desktop_2012.vcxproj
          │   │   │   ├── Texconv_Desktop_2012.vcxproj.filters
          │   │   │   ├── Texconv_Desktop_2013.vcxproj
          │   │   │   ├── Texconv_Desktop_2013.vcxproj.filters
          │   │   │   ├── Texconv_Desktop_2015.vcxproj
          │   │   │   └── Texconv_Desktop_2015.vcxproj.filters
          │   │   ├── Texassemble/
          │   │   │   ├── directx.ico
          │   │   │   ├── texassemble.cpp
          │   │   │   ├── texassemble.rc
          │   │   │   ├── Texassemble_Desktop_2012.vcxproj
          │   │   │   ├── Texassemble_Desktop_2012.vcxproj.filters
          │   │   │   ├── Texassemble_Desktop_2013.vcxproj
          │   │   │   ├── Texassemble_Desktop_2013.vcxproj.filters
          │   │   │   ├── Texassemble_Desktop_2015.vcxproj
          │   │   │   └── Texassemble_Desktop_2015.vcxproj.filters
          │   │   ├── ScreenGrab/
          │   │   │   ├── ScreenGrab.cpp
          │   │   │   └── ScreenGrab.h
          │   │   ├── DirectXTex/
          │   │   │   ├── BC.cpp
          │   │   │   ├── BC.h
          │   │   │   ├── BC4BC5.cpp
          │   │   │   ├── BC6HBC7.cpp
          │   │   │   ├── BCDirectCompute.cpp
          │   │   │   ├── BCDirectCompute.h
          │   │   │   ├── DDS.h
          │   │   │   ├── DirectXTex.h
          │   │   │   ├── DirectXTex.inl
          │   │   │   ├── DirectXTexCompress.cpp
          │   │   │   ├── DirectXTexCompressGPU.cpp
          │   │   │   ├── DirectXTexConvert.cpp
          │   │   │   ├── DirectXTexD3D11.cpp
          │   │   │   ├── DirectXTexDDS.cpp
          │   │   │   ├── DirectXTexFlipRotate.cpp
          │   │   │   ├── DirectXTexImage.cpp
          │   │   │   ├── DirectXTexMipmaps.cpp
          │   │   │   ├── DirectXTexMisc.cpp
          │   │   │   ├── DirectXTexNormalMaps.cpp
          │   │   │   ├── DirectXTexP.h
          │   │   │   ├── DirectXTexPMAlpha.cpp
          │   │   │   ├── DirectXTexResize.cpp
          │   │   │   ├── DirectXTexTGA.cpp
          │   │   │   ├── DirectXTexUtil.cpp
          │   │   │   ├── DirectXTexWIC.cpp
          │   │   │   ├── DirectXTex_Desktop_2012.vcxproj
          │   │   │   ├── DirectXTex_Desktop_2012.vcxproj.filters
          │   │   │   ├── DirectXTex_Desktop_2013.sln
          │   │   │   ├── DirectXTex_Desktop_2013.v12.suo
          │   │   │   ├── DirectXTex_Desktop_2013.vcxproj
          │   │   │   ├── DirectXTex_Desktop_2013.vcxproj.filters
          │   │   │   ├── DirectXTex_Desktop_2013.vcxproj.user
          │   │   │   ├── DirectXTex_Desktop_2015.v12.suo
          │   │   │   ├── DirectXTex_Desktop_2015.vcxproj
          │   │   │   ├── DirectXTex_Desktop_2015.vcxproj.filters
          │   │   │   ├── DirectXTex_Windows10.vcxproj
          │   │   │   ├── DirectXTex_Windows10.vcxproj.filters
          │   │   │   ├── DirectXTex_Windows81.vcxproj
          │   │   │   ├── DirectXTex_Windows81.vcxproj.filters
          │   │   │   ├── DirectXTex_WindowsPhone81.vcxproj
          │   │   │   ├── DirectXTex_WindowsPhone81.vcxproj.filters
          │   │   │   ├── DirectXTex_XboxOneADK.vcxproj
          │   │   │   ├── DirectXTex_XboxOneADK.vcxproj.filters
          │   │   │   ├── DirectXTex_XboxOneXDK.vcxproj
          │   │   │   ├── DirectXTex_XboxOneXDK.vcxproj.filters
          │   │   │   ├── DirectXTex_XboxOneXDK_2015.vcxproj
          │   │   │   ├── DirectXTex_XboxOneXDK_2015.vcxproj.filters
          │   │   │   ├── Filters.h
          │   │   │   ├── scoped.h
          │   │   │   ├── Shaders/
          │   │   │   │   ├── BC6HEncode.hlsl
          │   │   │   │   ├── BC7Encode.hlsl
          │   │   │   │   ├── CompileShaders.cmd
          │   │   │   │   └── Compiled/
          │   │   │   │       ├── BC6HEncode_EncodeBlockCS.inc
          │   │   │   │       ├── BC6HEncode_TryModeG10CS.inc
          │   │   │   │       ├── BC6HEncode_TryModeLE10CS.inc
          │   │   │   │       ├── BC7Encode_EncodeBlockCS.inc
          │   │   │   │       ├── BC7Encode_TryMode02CS.inc
          │   │   │   │       ├── BC7Encode_TryMode137CS.inc
          │   │   │   │       └── BC7Encode_TryMode456CS.inc
          │   │   │   └── Bin/
          │   │   │       └── Desktop_2013/
          │   │   │           ├── x64/
          │   │   │           │   ├── Release/
          │   │   │           │   │   └── DirectXTex.lib
          │   │   │           │   └── Debug/
          │   │   │           │       └── DirectXTex.lib
          │   │   │           └── Win32/
          │   │   │               ├── Release/
          │   │   │               │   └── DirectXTex.lib
          │   │   │               └── Debug/
          │   │   │                   └── DirectXTex.lib
          │   │   ├── DDSView/
          │   │   │   ├── ddsview.cpp
          │   │   │   ├── ddsview.fx
          │   │   │   ├── DDSView.rc
          │   │   │   ├── DDSView_Desktop_2012.vcxproj
          │   │   │   ├── DDSView_Desktop_2012.vcxproj.filters
          │   │   │   ├── DDSView_Desktop_2013.vcxproj
          │   │   │   ├── DDSView_Desktop_2013.vcxproj.filters
          │   │   │   ├── DDSView_Desktop_2015.vcxproj
          │   │   │   ├── DDSView_Desktop_2015.vcxproj.filters
          │   │   │   ├── directx.ico
          │   │   │   ├── hlsl.cmd
          │   │   │   └── shaders/
          │   │   │       ├── ps1D.h
          │   │   │       ├── ps1Darray.h
          │   │   │       ├── ps2D.h
          │   │   │       ├── ps2Darray.h
          │   │   │       ├── ps3D.h
          │   │   │       ├── psCube.h
          │   │   │       └── vs.h
          │   │   └── DDSTextureLoader/
          │   │       ├── DDSTextureLoader.cpp
          │   │       └── DDSTextureLoader.h
          │   ├── ddraw/
          │   │   ├── ddrawtypes.h
          │   │   ├── enums.h
          │   │   ├── kddraw.cpp
          │   │   ├── kddraw.h
          │   │   ├── macro.h
          │   │   ├── preddraw.cpp
          │   │   ├── preddraw.h
          │   │   ├── surface.cpp
          │   │   ├── surface.h
          │   │   ├── surfacesave.cpp
          │   │   ├── surfacesave.h
          │   │   └── surface_ripper.cpp
          │   └── common/
          │       ├── commontypes.h
          │       ├── d3dhelper.cpp
          │       ├── d3dhelper.h
          │       ├── dataconvert.cpp
          │       ├── dataconvert.h
          │       ├── datatypes.cpp
          │       ├── datatypes.h
          │       ├── fvf.cpp
          │       ├── fvf.h
          │       ├── guidtoname.cpp
          │       ├── guidtoname.h
          │       ├── indexprocess.cpp
          │       ├── indexprocess.h
          │       ├── iripper.h
          │       ├── khook.cpp
          │       ├── khook.h
          │       ├── khookmgr.cpp
          │       ├── khookmgr.h
          │       ├── kintruder.cpp
          │       ├── kintruder.h
          │       ├── klog.h
          │       ├── macro.h
          │       ├── outtypes__.h
          │       ├── ripout.cpp
          │       ├── ripout.h
          │       ├── shadercompile.cpp
          │       ├── shadercompile.h
          │       ├── tdxref.h
          │       ├── tinitedval.h
          │       ├── tools.cpp
          │       ├── tools.h
          │       ├── topology.cpp
          │       ├── topology.h
          │       ├── vertexprocess.cpp
          │       ├── vertexprocess.h
          │       ├── vert_indx_dump.cpp
          │       └── vert_indx_dump.h
          ├── injector/
          │   ├── aboutdlg.cpp
          │   ├── aboutdlg.h
          │   ├── dxrip_.ico
          │   ├── Hyperlinks.cpp
          │   ├── Hyperlinks.h
          │   ├── Hyperlinks__.cpp
          │   ├── injector.cpp
          │   ├── injector.h
          │   ├── injector.rc
          │   ├── injector.sln
          │   ├── injector.suo
          │   ├── injector.v12.suo
          │   ├── injector.vcproj
          │   ├── injector.vcxproj
          │   ├── injector.vcxproj.filters
          │   ├── injector.vcxproj.user
          │   ├── Main.ico
          │   ├── paypal.bmp
          │   ├── paypal10.bmp
          │   ├── paypal5.bmp
          │   ├── RCa20616
          │   ├── resource.h
          │   ├── settingsdlg.cpp
          │   ├── stdafx.h
          │   ├── UpgradeLog.htm
          │   └── UpgradeLog.XML
          ├── common/
          │   ├── constants.cpp
          │   ├── constants.h
          │   ├── crashdump.cpp
          │   ├── crashdump.h
          │   ├── kinject.cpp
          │   ├── kinject.h
          │   ├── ksettings.cpp
          │   ├── ksettings.h
          │   ├── pathtools.cpp
          │   ├── pathtools.h
          │   ├── registry.cpp
          │   ├── registry.h
          │   └── tinylogger.h
          └── DXSDK/
              ├── DXSDK9/
              │   ├── Include/
              │   │   ├── comdecl.h
              │   │   ├── d3d.h
              │   │   ├── D3D10.h
              │   │   ├── D3D10effect.h
              │   │   ├── d3d10misc.h
              │   │   ├── d3d10sdklayers.h
              │   │   ├── D3D10shader.h
              │   │   ├── d3d8.h
              │   │   ├── d3d8caps.h
              │   │   ├── d3d8types.h
              │   │   ├── d3d9.h
              │   │   ├── d3d9caps.h
              │   │   ├── d3d9types.h
              │   │   ├── d3dcaps.h
              │   │   ├── d3drm.h
              │   │   ├── d3drmdef.h
              │   │   ├── d3drmobj.h
              │   │   ├── d3drmwin.h
              │   │   ├── d3dtypes.h
              │   │   ├── d3dvec.inl
              │   │   ├── D3DX10.h
              │   │   ├── d3dx10async.h
              │   │   ├── D3DX10core.h
              │   │   ├── D3DX10math.h
              │   │   ├── D3DX10math.inl
              │   │   ├── D3DX10mesh.h
              │   │   ├── D3DX10tex.h
              │   │   ├── d3dx9.h
              │   │   ├── d3dx9anim.h
              │   │   ├── d3dx9core.h
              │   │   ├── d3dx9effect.h
              │   │   ├── d3dx9math.h
              │   │   ├── d3dx9math.inl
              │   │   ├── d3dx9mesh.h
              │   │   ├── d3dx9shader.h
              │   │   ├── d3dx9shape.h
              │   │   ├── d3dx9tex.h
              │   │   ├── d3dx9xof.h
              │   │   ├── ddraw.h
              │   │   ├── dinput.h
              │   │   ├── dinputd.h
              │   │   ├── dls1.h
              │   │   ├── dls2.h
              │   │   ├── dmdls.h
              │   │   ├── dmerror.h
              │   │   ├── dmksctrl.h
              │   │   ├── dmplugin.h
              │   │   ├── dmusbuff.h
              │   │   ├── dmusicc.h
              │   │   ├── dmusicf.h
              │   │   ├── dmusici.h
              │   │   ├── dmusics.h
              │   │   ├── dpaddr.h
              │   │   ├── dplay.h
              │   │   ├── dplay8.h
              │   │   ├── dplobby.h
              │   │   ├── dplobby8.h
              │   │   ├── dpnathlp.h
              │   │   ├── dsconf.h
              │   │   ├── dsetup.h
              │   │   ├── dsound.h
              │   │   ├── dvoice.h
              │   │   ├── dvp.h
              │   │   ├── dx7todx8.h
              │   │   ├── dxdiag.h
              │   │   ├── DxErr.h
              │   │   ├── dxerr8.h
              │   │   ├── dxerr9.h
              │   │   ├── dxfile.h
              │   │   ├── DXGI.h
              │   │   ├── DXGIType.h
              │   │   ├── dxsdkver.h
              │   │   ├── dxtrans.h
              │   │   ├── multimon.h
              │   │   ├── PIXPlugin.h
              │   │   ├── rmxfguid.h
              │   │   ├── rmxftmpl.h
              │   │   ├── strsafe.h
              │   │   ├── X3DAudio.h
              │   │   ├── xact.h
              │   │   ├── xact2wb.h
              │   │   ├── xact3d.h
              │   │   └── XInput.h
              │   └── Lib/
              │       ├── x86/
              │       │   ├── d3d10.lib
              │       │   ├── d3d8.lib
              │       │   ├── d3d9.lib
              │       │   ├── d3dx10.lib
              │       │   ├── d3dx10d.lib
              │       │   ├── d3dx9.lib
              │       │   ├── d3dx9d.lib
              │       │   ├── d3dxof.lib
              │       │   ├── ddraw.lib
              │       │   ├── dinput.lib
              │       │   ├── dinput8.lib
              │       │   ├── dplayx.lib
              │       │   ├── dsetup.lib
              │       │   ├── dsound.lib
              │       │   ├── DxErr.lib
              │       │   ├── DxErr8.lib
              │       │   ├── DxErr9.lib
              │       │   ├── dxgi.lib
              │       │   ├── dxguid.lib
              │       │   ├── dxtrans.lib
              │       │   ├── X3DAudio.lib
              │       │   └── XInput.lib
              │       └── x64/
              │           ├── d3d10.lib
              │           ├── d3d9.lib
              │           ├── d3dx10.lib
              │           ├── d3dx10d.lib
              │           ├── d3dx9.lib
              │           ├── d3dx9d.lib
              │           ├── d3dxof.lib
              │           ├── ddraw.lib
              │           ├── dinput.lib
              │           ├── dinput8.lib
              │           ├── dplayx.lib
              │           ├── dsound.lib
              │           ├── DxErr.lib
              │           ├── DxErr8.lib
              │           ├── DxErr9.lib
              │           ├── dxgi.lib
              │           ├── dxguid.lib
              │           ├── dxtrans.lib
              │           ├── X3DAudio.lib
              │           └── XInput.lib
              ├── DXSDK8/
              │   ├── lib/
              │   │   ├── amstrmid.lib
              │   │   ├── d3d8.lib
              │   │   ├── d3dx.lib
              │   │   ├── d3dx8.lib
              │   │   ├── d3dx8d.lib
              │   │   ├── d3dx8dt.lib
              │   │   ├── d3dxd.lib
              │   │   ├── d3dxof.lib
              │   │   ├── ddraw.lib
              │   │   ├── dinput.lib
              │   │   ├── dinput8.lib
              │   │   ├── dmoguids.lib
              │   │   ├── dplayx.lib
              │   │   ├── dsetup.lib
              │   │   ├── dsound.lib
              │   │   ├── DxErr8.lib
              │   │   ├── dxguid.lib
              │   │   ├── dxtrans.lib
              │   │   ├── ksproxy.lib
              │   │   ├── ksuser.lib
              │   │   ├── msdmo.lib
              │   │   ├── quartz.lib
              │   │   └── strmiids.lib
              │   └── include/
              │       ├── activecf.h
              │       ├── amaudio.h
              │       ├── amparse.h
              │       ├── amstream.h
              │       ├── amva.h
              │       ├── Amvideo.h
              │       ├── atsmedia.h
              │       ├── audevcod.h
              │       ├── austream.h
              │       ├── aviriff.h
              │       ├── basetsd.h
              │       ├── bdaiface.h
              │       ├── bdamedia.h
              │       ├── Bdatif.h
              │       ├── bdatypes.h
              │       ├── comlite.h
              │       ├── control.h
              │       ├── d3d.h
              │       ├── d3d8.h
              │       ├── d3d8caps.h
              │       ├── d3d8types.h
              │       ├── d3dcaps.h
              │       ├── d3drm.h
              │       ├── d3drmdef.h
              │       ├── d3drmobj.h
              │       ├── d3drmwin.h
              │       ├── d3dtypes.h
              │       ├── d3dvec.inl
              │       ├── d3dx.h
              │       ├── d3dx8.h
              │       ├── d3dx8core.h
              │       ├── d3dx8effect.h
              │       ├── d3dx8math.h
              │       ├── d3dx8math.inl
              │       ├── d3dx8mesh.h
              │       ├── d3dx8shape.h
              │       ├── d3dx8tex.h
              │       ├── d3dxcore.h
              │       ├── d3dxerr.h
              │       ├── d3dxmath.h
              │       ├── d3dxmath.inl
              │       ├── d3dxshapes.h
              │       ├── d3dxsprite.h
              │       ├── ddraw.h
              │       ├── ddrawex.h
              │       ├── ddstream.h
              │       ├── dinput.h
              │       ├── dinputd.h
              │       ├── dls1.h
              │       ├── dls2.h
              │       ├── dmdls.h
              │       ├── dmerror.h
              │       ├── dmksctrl.h
              │       ├── dmo.h
              │       ├── dmodshow.h
              │       ├── dmoimpl.h
              │       ├── dmoreg.h
              │       ├── dmort.h
              │       ├── dmplugin.h
              │       ├── dmusbuff.h
              │       ├── dmusicc.h
              │       ├── dmusicf.h
              │       ├── dmusici.h
              │       ├── dmusics.h
              │       ├── dpaddr.h
              │       ├── dplay.h
              │       ├── dplay8.h
              │       ├── dplobby.h
              │       ├── dplobby8.h
              │       ├── dsetup.h
              │       ├── DShow.h
              │       ├── dshowasf.h
              │       ├── dsound.h
              │       ├── dv.h
              │       ├── dvdevcod.h
              │       ├── dvdmedia.h
              │       ├── dvoice.h
              │       ├── dvp.h
              │       ├── dx7todx8.h
              │       ├── dxerr8.h
              │       ├── dxfile.h
              │       ├── dxsdk.inc
              │       ├── dxtrans.h
              │       ├── dxva.h
              │       ├── edevdefs.h
              │       ├── errors.h
              │       ├── evcode.h
              │       ├── il21dec.h
              │       ├── Iwstdec.h
              │       ├── ks.h
              │       ├── ksguid.h
              │       ├── ksmedia.h
              │       ├── ksproxy.h
              │       ├── ksuuids.h
              │       ├── mediaerr.h
              │       ├── mediaobj.h
              │       ├── medparam.h
              │       ├── mmstream.h
              │       ├── mpconfig.h
              │       ├── mpegtype.h
              │       ├── Mstvca.h
              │       ├── Mstve.h
              │       ├── Msvidctl.h
              │       ├── Msvidctl.tlb
              │       ├── multimon.h
              │       ├── playlist.h
              │       ├── qedit.h
              │       ├── qnetwork.h
              │       ├── regbag.h
              │       ├── rmxfguid.h
              │       ├── rmxftmpl.h
              │       ├── Segment.h
              │       ├── strmif.h
              │       ├── tune.h
              │       ├── tuner.h
              │       ├── Tuner.tlb
              │       ├── uuids.h
              │       ├── vfwmsgs.h
              │       ├── videoacc.h
              │       ├── vpconfig.h
              │       ├── vpnotify.h
              │       ├── vptype.h
              │       ├── xprtdefs.h
              │       └── DShowIDL/
              │           ├── amstream.idl
              │           ├── amvpe.idl
              │           ├── austream.idl
              │           ├── axcore.idl
              │           ├── axextend.idl
              │           ├── bdaiface.idl
              │           ├── Bdatif.idl
              │           ├── control.odl
              │           ├── ddstream.idl
              │           ├── devenum.idl
              │           ├── dmodshow.idl
              │           ├── dshowasf.idl
              │           ├── dvdif.idl
              │           ├── dxtrans.idl
              │           ├── dyngraph.idl
              │           ├── iamovie.idl
              │           ├── mediaobj.idl
              │           ├── medparam.idl
              │           ├── mmstream.idl
              │           ├── Mstvca.idl
              │           ├── mstve.idl
              │           ├── Mstvgs.idl
              │           ├── Msvidctl.idl
              │           ├── qedit.idl
              │           ├── regbag.idl
              │           ├── Segment.idl
              │           ├── strmif.idl
              │           ├── tuner.idl
              │           ├── Videoacc.idl
              │           └── Vmrender.idl
              ├── DXSDK7/
              │   ├── lib/
              │   │   ├── d3dim.lib
              │   │   ├── d3drm.lib
              │   │   ├── d3dx.lib
              │   │   ├── d3dxd.lib
              │   │   ├── d3dxof.lib
              │   │   ├── ddraw.lib
              │   │   ├── dinput.lib
              │   │   ├── dplayx.lib
              │   │   ├── DSETUP.lib
              │   │   ├── dsound.lib
              │   │   ├── dxguid.lib
              │   │   └── Borland/
              │   │       ├── d3dim.lib
              │   │       ├── d3drm.lib
              │   │       ├── d3dxof.lib
              │   │       ├── ddraw.lib
              │   │       ├── dinput.lib
              │   │       ├── dplayx.lib
              │   │       ├── dsetup.lib
              │   │       ├── dsound.lib
              │   │       └── dxguid.lib
              │   └── include/
              │       ├── d3d.h
              │       ├── d3dcaps.h
              │       ├── d3drm.h
              │       ├── d3drmdef.h
              │       ├── d3drmobj.h
              │       ├── d3drmwin.h
              │       ├── d3dtypes.h
              │       ├── d3dvec.inl
              │       ├── d3dx.h
              │       ├── d3dxcore.h
              │       ├── d3dxerr.h
              │       ├── d3dxmath.h
              │       ├── d3dxmath.inl
              │       ├── d3dxshapes.h
              │       ├── d3dxsprite.h
              │       ├── ddraw.h
              │       ├── dinput.h
              │       ├── dinputd.h
              │       ├── dls1.h
              │       ├── dls2.h
              │       ├── dmdls.h
              │       ├── dmerror.h
              │       ├── dmksctrl.h
              │       ├── dmusbuff.h
              │       ├── dmusicc.h
              │       ├── dmusicf.h
              │       ├── dmusici.h
              │       ├── dplay.h
              │       ├── dplobby.h
              │       ├── dsetup.h
              │       ├── dsound.h
              │       ├── dvp.h
              │       ├── dxfile.h
              │       ├── dxsdk.inc
              │       ├── multimon.h
              │       ├── rmxfguid.h
              │       ├── rmxftmpl.h
              │       └── rmxftmpl.x
              └── DXSDK11/
                  ├── Include/
                  │   ├── audiodefs.h
                  │   ├── comdecl.h
                  │   ├── D2D1.h
                  │   ├── D2D1Helper.h
                  │   ├── D2DBaseTypes.h
                  │   ├── D2Derr.h
                  │   ├── D3D10.h
                  │   ├── D3D10effect.h
                  │   ├── d3d10misc.h
                  │   ├── d3d10sdklayers.h
                  │   ├── D3D10shader.h
                  │   ├── D3D10_1.h
                  │   ├── D3D10_1shader.h
                  │   ├── D3D11.h
                  │   ├── D3D11SDKLayers.h
                  │   ├── D3D11Shader.h
                  │   ├── d3d9.h
                  │   ├── d3d9caps.h
                  │   ├── d3d9types.h
                  │   ├── D3Dcommon.h
                  │   ├── D3Dcompiler.h
                  │   ├── D3DCSX.h
                  │   ├── D3DX10.h
                  │   ├── d3dx10async.h
                  │   ├── D3DX10core.h
                  │   ├── D3DX10math.h
                  │   ├── D3DX10math.inl
                  │   ├── D3DX10mesh.h
                  │   ├── D3DX10tex.h
                  │   ├── D3DX11.h
                  │   ├── D3DX11async.h
                  │   ├── D3DX11core.h
                  │   ├── D3DX11tex.h
                  │   ├── d3dx9.h
                  │   ├── d3dx9anim.h
                  │   ├── d3dx9core.h
                  │   ├── d3dx9effect.h
                  │   ├── d3dx9math.h
                  │   ├── d3dx9math.inl
                  │   ├── d3dx9mesh.h
                  │   ├── d3dx9shader.h
                  │   ├── d3dx9shape.h
                  │   ├── d3dx9tex.h
                  │   ├── d3dx9xof.h
                  │   ├── D3DX_DXGIFormatConvert.inl
                  │   ├── Dcommon.h
                  │   ├── dinput.h
                  │   ├── dinputd.h
                  │   ├── dsconf.h
                  │   ├── dsetup.h
                  │   ├── dsound.h
                  │   ├── DWrite.h
                  │   ├── dxdiag.h
                  │   ├── DxErr.h
                  │   ├── dxfile.h
                  │   ├── DXGI.h
                  │   ├── DXGIFormat.h
                  │   ├── DXGIType.h
                  │   ├── dxsdkver.h
                  │   ├── gameux.h
                  │   ├── PIXPlugin.h
                  │   ├── rmxfguid.h
                  │   ├── rmxftmpl.h
                  │   ├── rpcsal.h
                  │   ├── X3DAudio.h
                  │   ├── xact3.h
                  │   ├── xact3d3.h
                  │   ├── xact3wb.h
                  │   ├── XAPO.h
                  │   ├── XAPOBase.h
                  │   ├── XAPOFX.h
                  │   ├── XAudio2.h
                  │   ├── XAudio2fx.h
                  │   ├── XDSP.h
                  │   ├── XInput.h
                  │   ├── xma2defs.h
                  │   ├── xnamath.h
                  │   ├── xnamathconvert.inl
                  │   ├── xnamathmatrix.inl
                  │   ├── xnamathmisc.inl
                  │   └── xnamathvector.inl
                  └── Lib/
                      ├── x86/
                      │   ├── d2d1.lib
                      │   ├── d3d10.lib
                      │   ├── d3d10_1.lib
                      │   ├── d3d11.lib
                      │   ├── d3d9.lib
                      │   ├── d3dcompiler.lib
                      │   ├── D3DCSX.lib
                      │   ├── D3DCSXd.lib
                      │   ├── d3dx10.lib
                      │   ├── d3dx10d.lib
                      │   ├── d3dx11.lib
                      │   ├── d3dx11d.lib
                      │   ├── d3dx9.lib
                      │   ├── d3dx9d.lib
                      │   ├── d3dxof.lib
                      │   ├── dinput8.lib
                      │   ├── dsetup.lib
                      │   ├── dsound.lib
                      │   ├── dwrite.lib
                      │   ├── DxErr.lib
                      │   ├── dxgi.lib
                      │   ├── dxguid.lib
                      │   ├── X3DAudio.lib
                      │   ├── xapobase.lib
                      │   ├── xapobased.lib
                      │   ├── XAPOFX.lib
                      │   └── XInput.lib
                      └── x64/
                          ├── d2d1.lib
                          ├── d3d10.lib
                          ├── d3d10_1.lib
                          ├── d3d11.lib
                          ├── d3d9.lib
                          ├── d3dcompiler.lib
                          ├── D3DCSX.lib
                          ├── D3DCSXd.lib
                          ├── d3dx10.lib
                          ├── d3dx10d.lib
                          ├── d3dx11.lib
                          ├── d3dx11d.lib
                          ├── d3dx9.lib
                          ├── d3dx9d.lib
                          ├── d3dxof.lib
                          ├── dinput8.lib
                          ├── dsound.lib
                          ├── dwrite.lib
                          ├── DxErr.lib
                          ├── dxgi.lib
                          ├── dxguid.lib
                          ├── X3DAudio.lib
                          ├── xapobase.lib
                          ├── xapobased.lib
                          ├── XAPOFX.lib
                          └── XInput.lib
    
