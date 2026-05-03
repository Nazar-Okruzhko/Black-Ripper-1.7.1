# Project NinjaRipper: Reborn - Black Ripper 1.7.1

# W.I.P. Project => Project is under a lot of the digging....

### Original NinjaRipper 1.7.1 Source Folder:

<img width="718" height="451" alt="Screenshot (3289)" src="https://github.com/user-attachments/assets/1ab20d10-4b3d-467f-a9af-5163ed987554" />

### Original NinjaRipper 1.7.1 Structure:
      └── NinjaRipperSrc_x64/
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
          └── DXSDK/ [OPTIONAL]
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
    
# Overview & History
<img width="456" height="282" alt="Screenshot (3434)" src="https://github.com/user-attachments/assets/39cc6793-9788-41c0-8820-4cba3791529d" />

I've took a look once again on what made the Original NinjaRipper 1.7.1 Great. I've tried analyzing it, inspecting it step by step behaviourally, tried to understand the injection mechanism, and even decompiling, and eventually... I've got very lucky! I've got the Original Source Code! From Black Ninja (The Original Author)! I've started analyzing it hardly and with some additional help soon I was able to start recreating it, it was so extreamly familiar to the Original that I've decided to Open Source this Version of the NinjaRipper 1.7.1 called Black Exploit, now Black Ripper. My goal was to have minimal files as possible, with good documented structure and extreamly easy to compile for everyone by a few commands....\

### The Files:
• NinjaRipper.exe (C++ or C#) = thin launcher. It just shows UI, calls CreateProcess(target, suspended) and injects intruder.dll via APC.C#.\
• injhelper.exe is a tiny ~150-line (C++ or C#) EXE. Its only job: receive pid tid dllpath on the command line, open the target process, and do the APC injection. It exists solely to handle the cross-arch case (64-bit launcher injecting into 32-bit game or vice versa). It's essentially just the KInject.InjectApc() method from BlackRipper.cs wrapped in a Main(). Could be written in any language like C#.\
• intruder.dll = the entire ripping engine. Compiled separately, runs inside the target game process. Completely self-contained. Never needs to talk back to the launcher. That one is native C++ only.\
• d3dwrap.dll = is a full DX wrapper — it exports d3d9.dll's actual API (Direct3DCreate9 etc.), forwards calls to the real system DLL, and loads intruder.dll via LoadLibrary from its own DllMain. It's an alternative injection path for games that can't be APC-injected. That one is native C++ only.
[Supports all the important DirectX Versions: DirectX 6, 7, 8, 9, 11....]

### I want especially thank Black Ninja (The Original Athor) for making this Project possible. Without him I would **NEVER** be able to get anywhere close to where I am now, remember he is the actual Author of NinjaRipper 1.7.1 I am just the guy who Ported it and Open Sourced. Please support Black Ninja through Patreon / Boosty (if possible) for creating this insane Program!
https://www.patreon.com/ninjaripper
https://boosty.to/ninjaripper

# Why not C# or Python?
Going fully on C# / Python is a very bad idea, C# and Python cannot do APC injection, vtable hooks, or LdrLoadDll interception at the native level. So Both intruder.dll & d3dwrap.dll must be in C++\
And intruder.dll is loaded by LoadLibraryW from inside the game process via APC. That means it must be a native Win32 DLL — a .NET assembly simply cannot be loaded this way.\
[Despite being my most beloved languages there was this one major problem, so I decided to only Make launcher and helper on C#]\

# How does the Ripper works? (Intruder injection)
It's essentially a DirexctX Geometry/Texture dumper (VRAM Exploit), for capturing runtime game's 3D/2D asset data.\
Mode 1 — Intruder Inject (APC)\
You launch the game frozen, shove the DLL path into its memory, tell it "load this when you wake up", then unfreeze it. The game never knows. Works on most games, fails on games with anti-cheat that monitors suspended-process launches.\
\
Mode 2 — d3dwrap.dll (Wrapper)\
Instead of injecting, you impersonate DirectX itself. You copy d3dwrap.dll into the game's folder and rename it d3d9.dll. When the game starts normally and calls Direct3DCreate9, Windows loads YOUR fake d3d9.dll instead of the real one. Your fake DLL does two things: loads the real system d3d9.dll and forwards the call to it, AND loads intruder.dll as a side effect. The game is completely unaware — it got the real DirectX back, just with a hitchhiker. Works on games that block APC injection but can't stop DLL loading from their own folder.\
\
What intruder.dll actually does once inside:\
It watches every DLL the game loads. The moment it sees d3d9.dll appear, it reaches into DirectX's internal function table (the COM vtable) and replaces the pointers for DrawPrimitive, DrawIndexedPrimitive, Present, SetTexture with its own functions. From that point forward, every time the game draws anything, intruder.dll's code runs first, reads the vertex and index buffers, unpacks them into floats, saves them as .rip files, renders each texture to an offscreen surface and saves it as .dds — then hands control back to the real DirectX so the game continues normally. The player presses F10, that flag flips on, one frame worth of geometry is captured, flag flips off. That's the entire thing.\

### Intruder Mode - Full Guide:
    BlackRipper.exe & InjHelper.exe:
        │
        ├─ 1. GetBinaryType(game.exe)                    → is it 32 or 64-bit?
        ├─ 2. CreateProcess(game, SUSPENDED)             → game thread frozen at ntdll init
        ├─ 3. VirtualAllocEx + WriteProcessMemory        → writes "intruder.dll" path into game RAM
        ├─ 4. QueueUserAPC(LoadLibraryW, thread, path)   → schedules DLL load
        └─ 5. ResumeThread                               → game thread wakes, processes the APC first
                                                         → Windows calls LoadLibraryW("intruder.dll")
                                                         → DllMain(DLL_PROCESS_ATTACH) fires
                                                         → install() runs inside the GAME process
    
    intruder.dll (inside the game process):
        │
        ├─ 1. Hooks ntdll.LdrLoadDll          → watches every DLL the game loads
        ├─ 2. Hooks CreateProcess*            → propagates to child processes
        │
        ├─ 3. Game loads d3d9.dll             → LdrLoadDll hook fires
        │     └─ create_KRipper9()            → hooks DrawPrimitive, DrawIndexedPrimitive,
        │                                       SetTexture, Present, CreateVertexBuffer...
        │
        ├─ 4. Every frame: game calls Present()
        │     └─ KIntruder::frameHandler()    → polls F10/F9/F12 hotkeys
        │
        ├─ 5. Player presses F10 (RipKey)
        │     └─ fRipEnabled = 1               → next Draw* calls start capturing
        │
        ├─ 6. Game calls DrawIndexedPrimitive()
        │     ├─ Lock vertex buffer           → read raw vertices
        │     ├─ Lock index buffer            → read raw indices
        │     ├─ processIndexes*()            → convert to triangle list
        │     ├─ dumpVertSemantic()           → unpack POSITION/NORMAL/TEXCOORD to floats
        │     ├─ GetTexture(0..7)             → render-to-texture trick → save as .dds
        │     └─ saveRipFile()                → write .rip file (header + faces + vertices)
        │
        └─ Player presses F10 again         → fRipEnabled = 0, frameEnd()
    [W.I.P.]


# Instructions
    Instructions:
    Requirments: .NET 4.8, MSVC 1.4
    //  Build X86:
    //  1. Build X86 Intruuder.dll (MSVC x86 Developer Command Prompt):
    //    cl /nologo /W3 /O2 /EHsc /LD /DUNICODE /D_UNICODE /D_WIN32_WINNT=0x0502
    //       intruder.cpp /Fe:intruder.dll
    //       /link /DLL d3d9.lib dxguid.lib kernel32.lib user32.lib
    //
    //  2. Build X64 BlackRipper.exe & InjHelper.exe (.NET 4-8):
    //    dotnet build injhelper.csproj -c Release -p:PlatformTarget=x86
    //    dotnet build BlackRipper_171.csproj -c Release -p:PlatformTarget=x86
    //
    //  Build X64:\
    //  1. Build X64 Intruder.dll (MSVC x64 Developer Command Prompt):
    //    cl /nologo /W3 /O2 /EHsc /LD /DUNICODE /D_UNICODE /D_WIN32_WINNT=0x0502
    //       /D_WIN64 intruder.cpp /Fe:intruder.dll
    //       /link /DLL d3d9.lib dxguid.lib kernel32.lib user32.lib
    //
    //  2. Build X64 BlackRipper.exe & InjHelper.exe (.NET 4-8):
    //    dotnet build injhelper.csproj -c Release -p:PlatformTarget=x64
    //    dotnet build BlackRipper_171.csproj -c Release -p:PlatformTarget=x64
