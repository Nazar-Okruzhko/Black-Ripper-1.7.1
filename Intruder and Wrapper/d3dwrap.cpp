// =============================================================================
//  d3dwrap.cpp  --  NinjaRipper D3D9 Wrapper DLL  (single-file build)
//  Merged from: d3d9.h + d3d9.cpp
//  Output:      d3dwrap.dll   (rename to d3d9.dll when deploying)
//
//  Build (MSVC x86 Developer Command Prompt):
//    cl /nologo /W3 /O2 /EHsc /LD /DUNICODE /D_UNICODE /D_WIN32_WINNT=0x0502
//       d3dwrap.cpp /Fe:d3dwrap.dll
//       /link /DLL d3d9.lib dxguid.lib kernel32.lib user32.lib
//
//  Build (MSVC x64):
//    cl /nologo /W3 /O2 /EHsc /LD /DUNICODE /D_UNICODE /D_WIN32_WINNT=0x0502
//       /D_WIN64 d3dwrap.cpp /Fe:d3dwrap.dll
//       /link /DLL d3d9.lib dxguid.lib kernel32.lib user32.lib
// =============================================================================
 
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _WIN32_WINNT 0x0502
#include <d3d9.h>
#include <windows.h>
 
// ---------------------------------------------------------------------------
//  Function-pointer type for the real Direct3DCreate9 export
// ---------------------------------------------------------------------------
typedef IDirect3D9 *(WINAPI *D3DC9)(UINT);
D3DC9 orig_Direct3DCreate9 = nullptr;
 
// ===========================================================================
//  Forward declarations of wrapper classes
// ===========================================================================
class f_iD3D9;
class f_IDirect3DDevice9;
 
// ===========================================================================
//  D3D Wrapper Class  (wraps IDirect3D9)
// ===========================================================================
class f_iD3D9 : public IDirect3D9
{
private:
    LPDIRECT3D9 f_pD3D;
 
public:
    f_iD3D9(LPDIRECT3D9 pDirect3D) { f_pD3D = pDirect3D; }
    f_iD3D9() { f_pD3D = nullptr; }
 
    /*** IUnknown ***/
    STDMETHOD(QueryInterface)(THIS_ REFIID riid, void** ppvObj);
    STDMETHOD_(ULONG, AddRef)(THIS);
    STDMETHOD_(ULONG, Release)(THIS);
 
    /*** IDirect3D9 ***/
    STDMETHOD(RegisterSoftwareDevice)(THIS_ void* pInitializeFunction);
    STDMETHOD_(UINT, GetAdapterCount)(THIS);
    STDMETHOD(GetAdapterIdentifier)(THIS_ UINT Adapter, DWORD Flags, D3DADAPTER_IDENTIFIER9* pIdentifier);
    STDMETHOD_(UINT, GetAdapterModeCount)(THIS_ UINT Adapter, D3DFORMAT Format);
    STDMETHOD(EnumAdapterModes)(THIS_ UINT Adapter, D3DFORMAT Format, UINT Mode, D3DDISPLAYMODE* pMode);
    STDMETHOD(GetAdapterDisplayMode)(THIS_ UINT Adapter, D3DDISPLAYMODE* pMode);
    STDMETHOD(CheckDeviceType)(THIS_ UINT Adapter, D3DDEVTYPE DevType, D3DFORMAT AdapterFormat, D3DFORMAT BackBufferFormat, BOOL bWindowed);
    STDMETHOD(CheckDeviceFormat)(THIS_ UINT Adapter, D3DDEVTYPE DeviceType, D3DFORMAT AdapterFormat, DWORD Usage, D3DRESOURCETYPE RType, D3DFORMAT CheckFormat);
    STDMETHOD(CheckDeviceMultiSampleType)(THIS_ UINT Adapter, D3DDEVTYPE DeviceType, D3DFORMAT SurfaceFormat, BOOL Windowed, D3DMULTISAMPLE_TYPE MultiSampleType, DWORD* pQualityLevels);
    STDMETHOD(CheckDepthStencilMatch)(THIS_ UINT Adapter, D3DDEVTYPE DeviceType, D3DFORMAT AdapterFormat, D3DFORMAT RenderTargetFormat, D3DFORMAT DepthStencilFormat);
    STDMETHOD(CheckDeviceFormatConversion)(THIS_ UINT Adapter, D3DDEVTYPE DeviceType, D3DFORMAT SourceFormat, D3DFORMAT TargetFormat);
    STDMETHOD(GetDeviceCaps)(THIS_ UINT Adapter, D3DDEVTYPE DeviceType, D3DCAPS9* pCaps);
    STDMETHOD_(HMONITOR, GetAdapterMonitor)(THIS_ UINT Adapter);
    STDMETHOD(CreateDevice)(THIS_ UINT Adapter, D3DDEVTYPE DeviceType, HWND hFocusWindow, DWORD BehaviorFlags, D3DPRESENT_PARAMETERS* pPresentationParameters, IDirect3DDevice9** ppReturnedDeviceInterface);
};
 
// ===========================================================================
//  Device Wrapper Class  (wraps IDirect3DDevice9)
// ===========================================================================
class f_IDirect3DDevice9 : public IDirect3DDevice9
{
private:
    LPDIRECT3DDEVICE9 f_pD3DDevice;
 
public:
    f_IDirect3DDevice9(LPDIRECT3DDEVICE9 pDevice, LPDIRECT3DDEVICE9 **ppDevice);
    f_IDirect3DDevice9() { f_pD3DDevice = nullptr; }
 
    /*** IUnknown ***/
    STDMETHOD(QueryInterface)(THIS_ REFIID riid, void** ppvObj);
    STDMETHOD_(ULONG, AddRef)(THIS);
    STDMETHOD_(ULONG, Release)(THIS);
 
    /*** IDirect3DDevice9 ***/
    STDMETHOD(TestCooperativeLevel)(THIS);
    STDMETHOD_(UINT, GetAvailableTextureMem)(THIS);
    STDMETHOD(EvictManagedResources)(THIS);
    STDMETHOD(GetDirect3D)(THIS_ IDirect3D9** ppD3D9);
    STDMETHOD(GetDeviceCaps)(THIS_ D3DCAPS9* pCaps);
    STDMETHOD(GetDisplayMode)(THIS_ UINT iSwapChain, D3DDISPLAYMODE* pMode);
    STDMETHOD(GetCreationParameters)(THIS_ D3DDEVICE_CREATION_PARAMETERS *pParameters);
    STDMETHOD(SetCursorProperties)(THIS_ UINT XHotSpot, UINT YHotSpot, IDirect3DSurface9* pCursorBitmap);
    STDMETHOD_(void, SetCursorPosition)(THIS_ int X, int Y, DWORD Flags);
    STDMETHOD_(BOOL, ShowCursor)(THIS_ BOOL bShow);
    STDMETHOD(CreateAdditionalSwapChain)(THIS_ D3DPRESENT_PARAMETERS* pPresentationParameters, IDirect3DSwapChain9** pSwapChain);
    STDMETHOD(GetSwapChain)(THIS_ UINT iSwapChain, IDirect3DSwapChain9** pSwapChain);
    STDMETHOD_(UINT, GetNumberOfSwapChains)(THIS);
    STDMETHOD(Reset)(THIS_ D3DPRESENT_PARAMETERS* pPresentationParameters);
    STDMETHOD(Present)(THIS_ CONST RECT* pSourceRect, CONST RECT* pDestRect, HWND hDestWindowOverride, CONST RGNDATA* pDirtyRegion);
    STDMETHOD(GetBackBuffer)(THIS_ UINT iSwapChain, UINT iBackBuffer, D3DBACKBUFFER_TYPE Type, IDirect3DSurface9** ppBackBuffer);
    STDMETHOD(GetRasterStatus)(THIS_ UINT iSwapChain, D3DRASTER_STATUS* pRasterStatus);
    STDMETHOD(SetDialogBoxMode)(THIS_ BOOL bEnableDialogs);
    STDMETHOD_(void, SetGammaRamp)(THIS_ UINT iSwapChain, DWORD Flags, CONST D3DGAMMARAMP* pRamp);
    STDMETHOD_(void, GetGammaRamp)(THIS_ UINT iSwapChain, D3DGAMMARAMP* pRamp);
    STDMETHOD(CreateTexture)(THIS_ UINT Width, UINT Height, UINT Levels, DWORD Usage, D3DFORMAT Format, D3DPOOL Pool, IDirect3DTexture9** ppTexture, HANDLE* pSharedHandle);
    STDMETHOD(CreateVolumeTexture)(THIS_ UINT Width, UINT Height, UINT Depth, UINT Levels, DWORD Usage, D3DFORMAT Format, D3DPOOL Pool, IDirect3DVolumeTexture9** ppVolumeTexture, HANDLE* pSharedHandle);
    STDMETHOD(CreateCubeTexture)(THIS_ UINT EdgeLength, UINT Levels, DWORD Usage, D3DFORMAT Format, D3DPOOL Pool, IDirect3DCubeTexture9** ppCubeTexture, HANDLE* pSharedHandle);
    STDMETHOD(CreateVertexBuffer)(THIS_ UINT Length, DWORD Usage, DWORD FVF, D3DPOOL Pool, IDirect3DVertexBuffer9** ppVertexBuffer, HANDLE* pSharedHandle);
    STDMETHOD(CreateIndexBuffer)(THIS_ UINT Length, DWORD Usage, D3DFORMAT Format, D3DPOOL Pool, IDirect3DIndexBuffer9** ppIndexBuffer, HANDLE* pSharedHandle);
    STDMETHOD(CreateRenderTarget)(THIS_ UINT Width, UINT Height, D3DFORMAT Format, D3DMULTISAMPLE_TYPE MultiSample, DWORD MultisampleQuality, BOOL Lockable, IDirect3DSurface9** ppSurface, HANDLE* pSharedHandle);
    STDMETHOD(CreateDepthStencilSurface)(THIS_ UINT Width, UINT Height, D3DFORMAT Format, D3DMULTISAMPLE_TYPE MultiSample, DWORD MultisampleQuality, BOOL Discard, IDirect3DSurface9** ppSurface, HANDLE* pSharedHandle);
    STDMETHOD(UpdateSurface)(THIS_ IDirect3DSurface9* pSourceSurface, CONST RECT* pSourceRect, IDirect3DSurface9* pDestinationSurface, CONST POINT* pDestPoint);
    STDMETHOD(UpdateTexture)(THIS_ IDirect3DBaseTexture9* pSourceTexture, IDirect3DBaseTexture9* pDestinationTexture);
    STDMETHOD(GetRenderTargetData)(THIS_ IDirect3DSurface9* pRenderTarget, IDirect3DSurface9* pDestSurface);
    STDMETHOD(GetFrontBufferData)(THIS_ UINT iSwapChain, IDirect3DSurface9* pDestSurface);
    STDMETHOD(StretchRect)(THIS_ IDirect3DSurface9* pSourceSurface, CONST RECT* pSourceRect, IDirect3DSurface9* pDestSurface, CONST RECT* pDestRect, D3DTEXTUREFILTERTYPE Filter);
    STDMETHOD(ColorFill)(THIS_ IDirect3DSurface9* pSurface, CONST RECT* pRect, D3DCOLOR color);
    STDMETHOD(CreateOffscreenPlainSurface)(THIS_ UINT Width, UINT Height, D3DFORMAT Format, D3DPOOL Pool, IDirect3DSurface9** ppSurface, HANDLE* pSharedHandle);
    STDMETHOD(SetRenderTarget)(THIS_ DWORD RenderTargetIndex, IDirect3DSurface9* pRenderTarget);
    STDMETHOD(GetRenderTarget)(THIS_ DWORD RenderTargetIndex, IDirect3DSurface9** ppRenderTarget);
    STDMETHOD(SetDepthStencilSurface)(THIS_ IDirect3DSurface9* pNewZStencil);
    STDMETHOD(GetDepthStencilSurface)(THIS_ IDirect3DSurface9** ppZStencilSurface);
    STDMETHOD(BeginScene)(THIS);
    STDMETHOD(EndScene)(THIS);
    STDMETHOD(Clear)(THIS_ DWORD Count, CONST D3DRECT* pRects, DWORD Flags, D3DCOLOR Color, float Z, DWORD Stencil);
    STDMETHOD(SetTransform)(THIS_ D3DTRANSFORMSTATETYPE State, CONST D3DMATRIX* pMatrix);
    STDMETHOD(GetTransform)(THIS_ D3DTRANSFORMSTATETYPE State, D3DMATRIX* pMatrix);
    STDMETHOD(MultiplyTransform)(THIS_ D3DTRANSFORMSTATETYPE, CONST D3DMATRIX*);
    STDMETHOD(SetViewport)(THIS_ CONST D3DVIEWPORT9* pViewport);
    STDMETHOD(GetViewport)(THIS_ D3DVIEWPORT9* pViewport);
    STDMETHOD(SetMaterial)(THIS_ CONST D3DMATERIAL9* pMaterial);
    STDMETHOD(GetMaterial)(THIS_ D3DMATERIAL9* pMaterial);
    STDMETHOD(SetLight)(THIS_ DWORD Index, CONST D3DLIGHT9*);
    STDMETHOD(GetLight)(THIS_ DWORD Index, D3DLIGHT9*);
    STDMETHOD(LightEnable)(THIS_ DWORD Index, BOOL Enable);
    STDMETHOD(GetLightEnable)(THIS_ DWORD Index, BOOL* pEnable);
    STDMETHOD(SetClipPlane)(THIS_ DWORD Index, CONST float* pPlane);
    STDMETHOD(GetClipPlane)(THIS_ DWORD Index, float* pPlane);
    STDMETHOD(SetRenderState)(THIS_ D3DRENDERSTATETYPE State, DWORD Value);
    STDMETHOD(GetRenderState)(THIS_ D3DRENDERSTATETYPE State, DWORD* pValue);
    STDMETHOD(CreateStateBlock)(THIS_ D3DSTATEBLOCKTYPE Type, IDirect3DStateBlock9** ppSB);
    STDMETHOD(BeginStateBlock)(THIS);
    STDMETHOD(EndStateBlock)(THIS_ IDirect3DStateBlock9** ppSB);
    STDMETHOD(SetClipStatus)(THIS_ CONST D3DCLIPSTATUS9* pClipStatus);
    STDMETHOD(GetClipStatus)(THIS_ D3DCLIPSTATUS9* pClipStatus);
    STDMETHOD(GetTexture)(THIS_ DWORD Stage, IDirect3DBaseTexture9** ppTexture);
    STDMETHOD(SetTexture)(THIS_ DWORD Stage, IDirect3DBaseTexture9* pTexture);
    STDMETHOD(GetTextureStageState)(THIS_ DWORD Stage, D3DTEXTURESTAGESTATETYPE Type, DWORD* pValue);
    STDMETHOD(SetTextureStageState)(THIS_ DWORD Stage, D3DTEXTURESTAGESTATETYPE Type, DWORD Value);
    STDMETHOD(GetSamplerState)(THIS_ DWORD Sampler, D3DSAMPLERSTATETYPE Type, DWORD* pValue);
    STDMETHOD(SetSamplerState)(THIS_ DWORD Sampler, D3DSAMPLERSTATETYPE Type, DWORD Value);
    STDMETHOD(ValidateDevice)(THIS_ DWORD* pNumPasses);
    STDMETHOD(SetPaletteEntries)(THIS_ UINT PaletteNumber, CONST PALETTEENTRY* pEntries);
    STDMETHOD(GetPaletteEntries)(THIS_ UINT PaletteNumber, PALETTEENTRY* pEntries);
    STDMETHOD(SetCurrentTexturePalette)(THIS_ UINT PaletteNumber);
    STDMETHOD(GetCurrentTexturePalette)(THIS_ UINT *PaletteNumber);
    STDMETHOD(SetScissorRect)(THIS_ CONST RECT* pRect);
    STDMETHOD(GetScissorRect)(THIS_ RECT* pRect);
    STDMETHOD(SetSoftwareVertexProcessing)(THIS_ BOOL bSoftware);
    STDMETHOD_(BOOL, GetSoftwareVertexProcessing)(THIS);
    STDMETHOD(SetNPatchMode)(THIS_ float nSegments);
    STDMETHOD_(float, GetNPatchMode)(THIS);
    STDMETHOD(DrawPrimitive)(THIS_ D3DPRIMITIVETYPE PrimitiveType, UINT StartVertex, UINT PrimitiveCount);
    STDMETHOD(DrawIndexedPrimitive)(THIS_ D3DPRIMITIVETYPE, INT BaseVertexIndex, UINT MinVertexIndex, UINT NumVertices, UINT startIndex, UINT primCount);
    STDMETHOD(DrawPrimitiveUP)(THIS_ D3DPRIMITIVETYPE PrimitiveType, UINT PrimitiveCount, CONST void* pVertexStreamZeroData, UINT VertexStreamZeroStride);
    STDMETHOD(DrawIndexedPrimitiveUP)(THIS_ D3DPRIMITIVETYPE PrimitiveType, UINT MinVertexIndex, UINT NumVertices, UINT PrimitiveCount, CONST void* pIndexData, D3DFORMAT IndexDataFormat, CONST void* pVertexStreamZeroData, UINT VertexStreamZeroStride);
    STDMETHOD(ProcessVertices)(THIS_ UINT SrcStartIndex, UINT DestIndex, UINT VertexCount, IDirect3DVertexBuffer9* pDestBuffer, IDirect3DVertexDeclaration9* pVertexDecl, DWORD Flags);
    STDMETHOD(CreateVertexDeclaration)(THIS_ CONST D3DVERTEXELEMENT9* pVertexElements, IDirect3DVertexDeclaration9** ppDecl);
    STDMETHOD(SetVertexDeclaration)(THIS_ IDirect3DVertexDeclaration9* pDecl);
    STDMETHOD(GetVertexDeclaration)(THIS_ IDirect3DVertexDeclaration9** ppDecl);
    STDMETHOD(SetFVF)(THIS_ DWORD FVF);
    STDMETHOD(GetFVF)(THIS_ DWORD* pFVF);
    STDMETHOD(CreateVertexShader)(THIS_ CONST DWORD* pFunction, IDirect3DVertexShader9** ppShader);
    STDMETHOD(SetVertexShader)(THIS_ IDirect3DVertexShader9* pShader);
    STDMETHOD(GetVertexShader)(THIS_ IDirect3DVertexShader9** ppShader);
    STDMETHOD(SetVertexShaderConstantF)(THIS_ UINT StartRegister, CONST float* pConstantData, UINT Vector4fCount);
    STDMETHOD(GetVertexShaderConstantF)(THIS_ UINT StartRegister, float* pConstantData, UINT Vector4fCount);
    STDMETHOD(SetVertexShaderConstantI)(THIS_ UINT StartRegister, CONST int* pConstantData, UINT Vector4iCount);
    STDMETHOD(GetVertexShaderConstantI)(THIS_ UINT StartRegister, int* pConstantData, UINT Vector4iCount);
    STDMETHOD(SetVertexShaderConstantB)(THIS_ UINT StartRegister, CONST BOOL* pConstantData, UINT BoolCount);
    STDMETHOD(GetVertexShaderConstantB)(THIS_ UINT StartRegister, BOOL* pConstantData, UINT BoolCount);
    STDMETHOD(SetStreamSource)(THIS_ UINT StreamNumber, IDirect3DVertexBuffer9* pStreamData, UINT OffsetInBytes, UINT Stride);
    STDMETHOD(GetStreamSource)(THIS_ UINT StreamNumber, IDirect3DVertexBuffer9** ppStreamData, UINT* pOffsetInBytes, UINT* pStride);
    STDMETHOD(SetStreamSourceFreq)(THIS_ UINT StreamNumber, UINT Setting);
    STDMETHOD(GetStreamSourceFreq)(THIS_ UINT StreamNumber, UINT* pSetting);
    STDMETHOD(SetIndices)(THIS_ IDirect3DIndexBuffer9* pIndexData);
    STDMETHOD(GetIndices)(THIS_ IDirect3DIndexBuffer9** ppIndexData);
    STDMETHOD(CreatePixelShader)(THIS_ CONST DWORD* pFunction, IDirect3DPixelShader9** ppShader);
    STDMETHOD(SetPixelShader)(THIS_ IDirect3DPixelShader9* pShader);
    STDMETHOD(GetPixelShader)(THIS_ IDirect3DPixelShader9** ppShader);
    STDMETHOD(SetPixelShaderConstantF)(THIS_ UINT StartRegister, CONST float* pConstantData, UINT Vector4fCount);
    STDMETHOD(GetPixelShaderConstantF)(THIS_ UINT StartRegister, float* pConstantData, UINT Vector4fCount);
    STDMETHOD(SetPixelShaderConstantI)(THIS_ UINT StartRegister, CONST int* pConstantData, UINT Vector4iCount);
    STDMETHOD(GetPixelShaderConstantI)(THIS_ UINT StartRegister, int* pConstantData, UINT Vector4iCount);
    STDMETHOD(SetPixelShaderConstantB)(THIS_ UINT StartRegister, CONST BOOL* pConstantData, UINT BoolCount);
    STDMETHOD(GetPixelShaderConstantB)(THIS_ UINT StartRegister, BOOL* pConstantData, UINT BoolCount);
    STDMETHOD(DrawRectPatch)(THIS_ UINT Handle, CONST float* pNumSegs, CONST D3DRECTPATCH_INFO* pRectPatchInfo);
    STDMETHOD(DrawTriPatch)(THIS_ UINT Handle, CONST float* pNumSegs, CONST D3DTRIPATCH_INFO* pTriPatchInfo);
    STDMETHOD(DeletePatch)(THIS_ UINT Handle);
    STDMETHOD(CreateQuery)(THIS_ D3DQUERYTYPE Type, IDirect3DQuery9** ppQuery);
};
 
// ===========================================================================
//  DllMain + exported factory
// ===========================================================================
 
IDirect3D9 *WINAPI f_Direct3DCreate9(UINT SDKVersion)
{
    return new f_iD3D9(orig_Direct3DCreate9(SDKVersion));
}
 
bool WINAPI DllMain(HMODULE hModule, DWORD fdwReason, LPVOID /*lpReserved*/)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
    {
        char path[MAX_PATH];
        GetSystemDirectoryA(path, MAX_PATH);
        strcat_s(path, MAX_PATH, "\\d3d9.dll");
        HMODULE hReal = LoadLibraryA(path);
        if (hReal)
            orig_Direct3DCreate9 = (D3DC9)GetProcAddress(hReal, "Direct3DCreate9");
        break;
    }
    case DLL_PROCESS_DETACH:
        // The real DLL is kept loaded for the process lifetime; Windows
        // will clean it up automatically on process exit.
        break;
    }
    return true;
}
 
// ===========================================================================
//  Augmented Callbacks  --  override these to add your own D3D logic
// ===========================================================================
 
HRESULT f_iD3D9::CreateDevice(UINT Adapter, D3DDEVTYPE DeviceType,
    HWND hFocusWindow, DWORD BehaviorFlags,
    D3DPRESENT_PARAMETERS *pPresentationParameters,
    IDirect3DDevice9 **ppReturnedDeviceInterface)
{
    HRESULT hr = f_pD3D->CreateDevice(Adapter, DeviceType, hFocusWindow,
        BehaviorFlags, pPresentationParameters, ppReturnedDeviceInterface);
    if (SUCCEEDED(hr))
    {
        LPDIRECT3DDEVICE9 *ppDev = ppReturnedDeviceInterface;
        f_IDirect3DDevice9 *wrapper =
            new f_IDirect3DDevice9(*ppReturnedDeviceInterface, &ppDev);
        *ppReturnedDeviceInterface = wrapper;
        // NOTE: initialise your custom D3D components here.
    }
    return hr;
}
 
HRESULT f_IDirect3DDevice9::Reset(D3DPRESENT_PARAMETERS *pPresentationParameters)
{
    // NOTE: call onLostDevice for custom D3D components here.
    HRESULT hr = f_pD3DDevice->Reset(pPresentationParameters);
    // NOTE: call onResetDevice for custom D3D components here.
    return hr;
}
 
HRESULT f_IDirect3DDevice9::EndScene()
{
    // NOTE: draw your custom D3D overlay components here.
    return f_pD3DDevice->EndScene();
}
 
// ===========================================================================
//  IDirect3D9 pass-through implementations
// ===========================================================================
 
ULONG   f_iD3D9::AddRef()    { return f_pD3D->AddRef(); }
ULONG   f_iD3D9::Release()   { return f_pD3D->Release(); }
HRESULT f_iD3D9::QueryInterface(REFIID riid, LPVOID *ppvObj) { return f_pD3D->QueryInterface(riid, ppvObj); }
 
HRESULT f_iD3D9::RegisterSoftwareDevice(void *pInitializeFunction)  { return f_pD3D->RegisterSoftwareDevice(pInitializeFunction); }
UINT    f_iD3D9::GetAdapterCount()                                   { return f_pD3D->GetAdapterCount(); }
HRESULT f_iD3D9::GetAdapterIdentifier(UINT Adapter, DWORD Flags, D3DADAPTER_IDENTIFIER9 *pIdentifier) { return f_pD3D->GetAdapterIdentifier(Adapter, Flags, pIdentifier); }
UINT    f_iD3D9::GetAdapterModeCount(UINT Adapter, D3DFORMAT Format) { return f_pD3D->GetAdapterModeCount(Adapter, Format); }
HRESULT f_iD3D9::EnumAdapterModes(UINT Adapter, D3DFORMAT Format, UINT Mode, D3DDISPLAYMODE *pMode) { return f_pD3D->EnumAdapterModes(Adapter, Format, Mode, pMode); }
HRESULT f_iD3D9::GetAdapterDisplayMode(UINT Adapter, D3DDISPLAYMODE *pMode) { return f_pD3D->GetAdapterDisplayMode(Adapter, pMode); }
HRESULT f_iD3D9::CheckDeviceType(UINT Adapter, D3DDEVTYPE CheckType, D3DFORMAT DisplayFormat, D3DFORMAT BackBufferFormat, BOOL Windowed) { return f_pD3D->CheckDeviceType(Adapter, CheckType, DisplayFormat, BackBufferFormat, Windowed); }
HRESULT f_iD3D9::CheckDeviceFormat(UINT Adapter, D3DDEVTYPE DeviceType, D3DFORMAT AdapterFormat, DWORD Usage, D3DRESOURCETYPE RType, D3DFORMAT CheckFormat) { return f_pD3D->CheckDeviceFormat(Adapter, DeviceType, AdapterFormat, Usage, RType, CheckFormat); }
HRESULT f_iD3D9::CheckDeviceMultiSampleType(UINT Adapter, D3DDEVTYPE DeviceType, D3DFORMAT SurfaceFormat, BOOL Windowed, D3DMULTISAMPLE_TYPE MultiSampleType, DWORD *pQualityLevels) { return f_pD3D->CheckDeviceMultiSampleType(Adapter, DeviceType, SurfaceFormat, Windowed, MultiSampleType, pQualityLevels); }
HRESULT f_iD3D9::CheckDepthStencilMatch(UINT Adapter, D3DDEVTYPE DeviceType, D3DFORMAT AdapterFormat, D3DFORMAT RenderTargetFormat, D3DFORMAT DepthStencilFormat) { return f_pD3D->CheckDepthStencilMatch(Adapter, DeviceType, AdapterFormat, RenderTargetFormat, DepthStencilFormat); }
HRESULT f_iD3D9::CheckDeviceFormatConversion(UINT Adapter, D3DDEVTYPE DeviceType, D3DFORMAT SourceFormat, D3DFORMAT TargetFormat) { return f_pD3D->CheckDeviceFormatConversion(Adapter, DeviceType, SourceFormat, TargetFormat); }
HRESULT f_iD3D9::GetDeviceCaps(UINT Adapter, D3DDEVTYPE DeviceType, D3DCAPS9 *pCaps) { return f_pD3D->GetDeviceCaps(Adapter, DeviceType, pCaps); }
HMONITOR f_iD3D9::GetAdapterMonitor(UINT Adapter) { return f_pD3D->GetAdapterMonitor(Adapter); }
 
// ===========================================================================
//  IDirect3DDevice9  --  constructor
// ===========================================================================
 
f_IDirect3DDevice9::f_IDirect3DDevice9(LPDIRECT3DDEVICE9 pDevice, LPDIRECT3DDEVICE9 **ppDevice)
{
    f_pD3DDevice = pDevice;
    *ppDevice = &f_pD3DDevice;
}
 
// ===========================================================================
//  IDirect3DDevice9  --  IUnknown pass-throughs
// ===========================================================================
 
ULONG   f_IDirect3DDevice9::AddRef()  { return f_pD3DDevice->AddRef(); }
ULONG   f_IDirect3DDevice9::Release() { return f_pD3DDevice->Release(); }
HRESULT f_IDirect3DDevice9::QueryInterface(REFIID riid, LPVOID *ppvObj) { return f_pD3DDevice->QueryInterface(riid, ppvObj); }
 
// ===========================================================================
//  IDirect3DDevice9  --  all remaining pass-throughs (alphabetical by method)
// ===========================================================================
 
HRESULT f_IDirect3DDevice9::BeginScene()  { return f_pD3DDevice->BeginScene(); }
HRESULT f_IDirect3DDevice9::BeginStateBlock() { return f_pD3DDevice->BeginStateBlock(); }
HRESULT f_IDirect3DDevice9::Clear(DWORD Count, CONST D3DRECT *pRects, DWORD Flags, D3DCOLOR Color, float Z, DWORD Stencil) { return f_pD3DDevice->Clear(Count, pRects, Flags, Color, Z, Stencil); }
HRESULT f_IDirect3DDevice9::ColorFill(IDirect3DSurface9 *pSurface, CONST RECT *pRect, D3DCOLOR color) { return f_pD3DDevice->ColorFill(pSurface, pRect, color); }
HRESULT f_IDirect3DDevice9::CreateAdditionalSwapChain(D3DPRESENT_PARAMETERS *pPresentationParameters, IDirect3DSwapChain9 **ppSwapChain) { return f_pD3DDevice->CreateAdditionalSwapChain(pPresentationParameters, ppSwapChain); }
HRESULT f_IDirect3DDevice9::CreateCubeTexture(UINT EdgeLength, UINT Levels, DWORD Usage, D3DFORMAT Format, D3DPOOL Pool, IDirect3DCubeTexture9 **ppCubeTexture, HANDLE *pSharedHandle) { return f_pD3DDevice->CreateCubeTexture(EdgeLength, Levels, Usage, Format, Pool, ppCubeTexture, pSharedHandle); }
HRESULT f_IDirect3DDevice9::CreateDepthStencilSurface(UINT Width, UINT Height, D3DFORMAT Format, D3DMULTISAMPLE_TYPE MultiSample, DWORD MultisampleQuality, BOOL Discard, IDirect3DSurface9 **ppSurface, HANDLE *pSharedHandle) { return f_pD3DDevice->CreateDepthStencilSurface(Width, Height, Format, MultiSample, MultisampleQuality, Discard, ppSurface, pSharedHandle); }
HRESULT f_IDirect3DDevice9::CreateIndexBuffer(UINT Length, DWORD Usage, D3DFORMAT Format, D3DPOOL Pool, IDirect3DIndexBuffer9 **ppIndexBuffer, HANDLE *pSharedHandle) { return f_pD3DDevice->CreateIndexBuffer(Length, Usage, Format, Pool, ppIndexBuffer, pSharedHandle); }
HRESULT f_IDirect3DDevice9::CreateOffscreenPlainSurface(UINT Width, UINT Height, D3DFORMAT Format, D3DPOOL Pool, IDirect3DSurface9 **ppSurface, HANDLE *pSharedHandle) { return f_pD3DDevice->CreateOffscreenPlainSurface(Width, Height, Format, Pool, ppSurface, pSharedHandle); }
HRESULT f_IDirect3DDevice9::CreatePixelShader(CONST DWORD *pFunction, IDirect3DPixelShader9 **ppShader) { return f_pD3DDevice->CreatePixelShader(pFunction, ppShader); }
HRESULT f_IDirect3DDevice9::CreateQuery(D3DQUERYTYPE Type, IDirect3DQuery9 **ppQuery) { return f_pD3DDevice->CreateQuery(Type, ppQuery); }
HRESULT f_IDirect3DDevice9::CreateRenderTarget(UINT Width, UINT Height, D3DFORMAT Format, D3DMULTISAMPLE_TYPE MultiSample, DWORD MultisampleQuality, BOOL Lockable, IDirect3DSurface9 **ppSurface, HANDLE *pSharedHandle) { return f_pD3DDevice->CreateRenderTarget(Width, Height, Format, MultiSample, MultisampleQuality, Lockable, ppSurface, pSharedHandle); }
HRESULT f_IDirect3DDevice9::CreateStateBlock(D3DSTATEBLOCKTYPE Type, IDirect3DStateBlock9 **ppSB) { return f_pD3DDevice->CreateStateBlock(Type, ppSB); }
HRESULT f_IDirect3DDevice9::CreateTexture(UINT Width, UINT Height, UINT Levels, DWORD Usage, D3DFORMAT Format, D3DPOOL Pool, IDirect3DTexture9 **ppTexture, HANDLE *pSharedHandle) { return f_pD3DDevice->CreateTexture(Width, Height, Levels, Usage, Format, Pool, ppTexture, pSharedHandle); }
HRESULT f_IDirect3DDevice9::CreateVertexBuffer(UINT Length, DWORD Usage, DWORD FVF, D3DPOOL Pool, IDirect3DVertexBuffer9 **ppVertexBuffer, HANDLE *pSharedHandle) { return f_pD3DDevice->CreateVertexBuffer(Length, Usage, FVF, Pool, ppVertexBuffer, pSharedHandle); }
HRESULT f_IDirect3DDevice9::CreateVertexDeclaration(CONST D3DVERTEXELEMENT9 *pVertexElements, IDirect3DVertexDeclaration9 **ppDecl) { return f_pD3DDevice->CreateVertexDeclaration(pVertexElements, ppDecl); }
HRESULT f_IDirect3DDevice9::CreateVertexShader(CONST DWORD *pFunction, IDirect3DVertexShader9 **ppShader) { return f_pD3DDevice->CreateVertexShader(pFunction, ppShader); }
HRESULT f_IDirect3DDevice9::CreateVolumeTexture(UINT Width, UINT Height, UINT Depth, UINT Levels, DWORD Usage, D3DFORMAT Format, D3DPOOL Pool, IDirect3DVolumeTexture9 **ppVolumeTexture, HANDLE *pSharedHandle) { return f_pD3DDevice->CreateVolumeTexture(Width, Height, Depth, Levels, Usage, Format, Pool, ppVolumeTexture, pSharedHandle); }
HRESULT f_IDirect3DDevice9::DeletePatch(UINT Handle) { return f_pD3DDevice->DeletePatch(Handle); }
HRESULT f_IDirect3DDevice9::DrawIndexedPrimitive(D3DPRIMITIVETYPE PrimitiveType, INT BaseVertexIndex, UINT MinVertexIndex, UINT NumVertices, UINT startIndex, UINT primCount) { return f_pD3DDevice->DrawIndexedPrimitive(PrimitiveType, BaseVertexIndex, MinVertexIndex, NumVertices, startIndex, primCount); }
HRESULT f_IDirect3DDevice9::DrawIndexedPrimitiveUP(D3DPRIMITIVETYPE PrimitiveType, UINT MinVertexIndex, UINT NumVertices, UINT PrimitiveCount, CONST void *pIndexData, D3DFORMAT IndexDataFormat, CONST void *pVertexStreamZeroData, UINT VertexStreamZeroStride) { return f_pD3DDevice->DrawIndexedPrimitiveUP(PrimitiveType, MinVertexIndex, NumVertices, PrimitiveCount, pIndexData, IndexDataFormat, pVertexStreamZeroData, VertexStreamZeroStride); }
HRESULT f_IDirect3DDevice9::DrawPrimitive(D3DPRIMITIVETYPE PrimitiveType, UINT StartVertex, UINT PrimitiveCount) { return f_pD3DDevice->DrawPrimitive(PrimitiveType, StartVertex, PrimitiveCount); }
HRESULT f_IDirect3DDevice9::DrawPrimitiveUP(D3DPRIMITIVETYPE PrimitiveType, UINT PrimitiveCount, CONST void *pVertexStreamZeroData, UINT VertexStreamZeroStride) { return f_pD3DDevice->DrawPrimitiveUP(PrimitiveType, PrimitiveCount, pVertexStreamZeroData, VertexStreamZeroStride); }
HRESULT f_IDirect3DDevice9::DrawRectPatch(UINT Handle, CONST float *pNumSegs, CONST D3DRECTPATCH_INFO *pRectPatchInfo) { return f_pD3DDevice->DrawRectPatch(Handle, pNumSegs, pRectPatchInfo); }
HRESULT f_IDirect3DDevice9::DrawTriPatch(UINT Handle, CONST float *pNumSegs, CONST D3DTRIPATCH_INFO *pTriPatchInfo) { return f_pD3DDevice->DrawTriPatch(Handle, pNumSegs, pTriPatchInfo); }
HRESULT f_IDirect3DDevice9::EndStateBlock(IDirect3DStateBlock9 **ppSB) { return f_pD3DDevice->EndStateBlock(ppSB); }
HRESULT f_IDirect3DDevice9::EvictManagedResources() { return f_pD3DDevice->EvictManagedResources(); }
UINT    f_IDirect3DDevice9::GetAvailableTextureMem() { return f_pD3DDevice->GetAvailableTextureMem(); }
HRESULT f_IDirect3DDevice9::GetBackBuffer(UINT iSwapChain, UINT iBackBuffer, D3DBACKBUFFER_TYPE Type, IDirect3DSurface9 **ppBackBuffer) { return f_pD3DDevice->GetBackBuffer(iSwapChain, iBackBuffer, Type, ppBackBuffer); }
HRESULT f_IDirect3DDevice9::GetClipPlane(DWORD Index, float *pPlane) { return f_pD3DDevice->GetClipPlane(Index, pPlane); }
HRESULT f_IDirect3DDevice9::GetClipStatus(D3DCLIPSTATUS9 *pClipStatus) { return f_pD3DDevice->GetClipStatus(pClipStatus); }
HRESULT f_IDirect3DDevice9::GetCreationParameters(D3DDEVICE_CREATION_PARAMETERS *pParameters) { return f_pD3DDevice->GetCreationParameters(pParameters); }
HRESULT f_IDirect3DDevice9::GetCurrentTexturePalette(UINT *PaletteNumber) { return f_pD3DDevice->GetCurrentTexturePalette(PaletteNumber); }
HRESULT f_IDirect3DDevice9::GetDepthStencilSurface(IDirect3DSurface9 **ppZStencilSurface) { return f_pD3DDevice->GetDepthStencilSurface(ppZStencilSurface); }
HRESULT f_IDirect3DDevice9::GetDeviceCaps(D3DCAPS9 *pCaps) { return f_pD3DDevice->GetDeviceCaps(pCaps); }
HRESULT f_IDirect3DDevice9::GetDirect3D(IDirect3D9 **ppD3D9) { return f_pD3DDevice->GetDirect3D(ppD3D9); }
HRESULT f_IDirect3DDevice9::GetDisplayMode(UINT iSwapChain, D3DDISPLAYMODE *pMode) { return f_pD3DDevice->GetDisplayMode(iSwapChain, pMode); }
HRESULT f_IDirect3DDevice9::GetFrontBufferData(UINT iSwapChain, IDirect3DSurface9 *pDestSurface) { return f_pD3DDevice->GetFrontBufferData(iSwapChain, pDestSurface); }
void    f_IDirect3DDevice9::GetGammaRamp(UINT iSwapChain, D3DGAMMARAMP *pRamp) { f_pD3DDevice->GetGammaRamp(iSwapChain, pRamp); }
HRESULT f_IDirect3DDevice9::GetIndices(IDirect3DIndexBuffer9 **ppIndexData) { return f_pD3DDevice->GetIndices(ppIndexData); }
HRESULT f_IDirect3DDevice9::GetLight(DWORD Index, D3DLIGHT9 *pLight) { return f_pD3DDevice->GetLight(Index, pLight); }
HRESULT f_IDirect3DDevice9::GetLightEnable(DWORD Index, BOOL *pEnable) { return f_pD3DDevice->GetLightEnable(Index, pEnable); }
HRESULT f_IDirect3DDevice9::GetMaterial(D3DMATERIAL9 *pMaterial) { return f_pD3DDevice->GetMaterial(pMaterial); }
UINT    f_IDirect3DDevice9::GetNumberOfSwapChains() { return f_pD3DDevice->GetNumberOfSwapChains(); }
HRESULT f_IDirect3DDevice9::GetPaletteEntries(UINT PaletteNumber, PALETTEENTRY *pEntries) { return f_pD3DDevice->GetPaletteEntries(PaletteNumber, pEntries); }
HRESULT f_IDirect3DDevice9::GetPixelShader(IDirect3DPixelShader9 **ppShader) { return f_pD3DDevice->GetPixelShader(ppShader); }
HRESULT f_IDirect3DDevice9::GetPixelShaderConstantB(UINT StartRegister, BOOL *pConstantData, UINT BoolCount) { return f_pD3DDevice->GetPixelShaderConstantB(StartRegister, pConstantData, BoolCount); }
HRESULT f_IDirect3DDevice9::GetPixelShaderConstantF(UINT StartRegister, float *pConstantData, UINT Vector4fCount) { return f_pD3DDevice->GetPixelShaderConstantF(StartRegister, pConstantData, Vector4fCount); }
HRESULT f_IDirect3DDevice9::GetPixelShaderConstantI(UINT StartRegister, int *pConstantData, UINT Vector4iCount) { return f_pD3DDevice->GetPixelShaderConstantI(StartRegister, pConstantData, Vector4iCount); }
HRESULT f_IDirect3DDevice9::GetRasterStatus(UINT iSwapChain, D3DRASTER_STATUS *pRasterStatus) { return f_pD3DDevice->GetRasterStatus(iSwapChain, pRasterStatus); }
HRESULT f_IDirect3DDevice9::GetRenderState(D3DRENDERSTATETYPE State, DWORD *pValue) { return f_pD3DDevice->GetRenderState(State, pValue); }
HRESULT f_IDirect3DDevice9::GetRenderTarget(DWORD RenderTargetIndex, IDirect3DSurface9 **ppRenderTarget) { return f_pD3DDevice->GetRenderTarget(RenderTargetIndex, ppRenderTarget); }
HRESULT f_IDirect3DDevice9::GetRenderTargetData(IDirect3DSurface9 *pRenderTarget, IDirect3DSurface9 *pDestSurface) { return f_pD3DDevice->GetRenderTargetData(pRenderTarget, pDestSurface); }
HRESULT f_IDirect3DDevice9::GetSamplerState(DWORD Sampler, D3DSAMPLERSTATETYPE Type, DWORD *pValue) { return f_pD3DDevice->GetSamplerState(Sampler, Type, pValue); }
HRESULT f_IDirect3DDevice9::GetScissorRect(RECT *pRect) { return f_pD3DDevice->GetScissorRect(pRect); }
BOOL    f_IDirect3DDevice9::GetSoftwareVertexProcessing() { return f_pD3DDevice->GetSoftwareVertexProcessing(); }
HRESULT f_IDirect3DDevice9::GetStreamSource(UINT StreamNumber, IDirect3DVertexBuffer9 **ppStreamData, UINT *pOffsetInBytes, UINT *pStride) { return f_pD3DDevice->GetStreamSource(StreamNumber, ppStreamData, pOffsetInBytes, pStride); }
HRESULT f_IDirect3DDevice9::GetStreamSourceFreq(UINT StreamNumber, UINT *pSetting) { return f_pD3DDevice->GetStreamSourceFreq(StreamNumber, pSetting); }
HRESULT f_IDirect3DDevice9::GetSwapChain(UINT iSwapChain, IDirect3DSwapChain9 **pSwapChain) { return f_pD3DDevice->GetSwapChain(iSwapChain, pSwapChain); }
HRESULT f_IDirect3DDevice9::GetTexture(DWORD Stage, IDirect3DBaseTexture9 **ppTexture) { return f_pD3DDevice->GetTexture(Stage, ppTexture); }
HRESULT f_IDirect3DDevice9::GetTextureStageState(DWORD Stage, D3DTEXTURESTAGESTATETYPE Type, DWORD *pValue) { return f_pD3DDevice->GetTextureStageState(Stage, Type, pValue); }
HRESULT f_IDirect3DDevice9::GetTransform(D3DTRANSFORMSTATETYPE State, D3DMATRIX *pMatrix) { return f_pD3DDevice->GetTransform(State, pMatrix); }
HRESULT f_IDirect3DDevice9::GetVertexDeclaration(IDirect3DVertexDeclaration9 **ppDecl) { return f_pD3DDevice->GetVertexDeclaration(ppDecl); }
HRESULT f_IDirect3DDevice9::GetVertexShader(IDirect3DVertexShader9 **ppShader) { return f_pD3DDevice->GetVertexShader(ppShader); }
HRESULT f_IDirect3DDevice9::GetVertexShaderConstantB(UINT StartRegister, BOOL *pConstantData, UINT BoolCount) { return f_pD3DDevice->GetVertexShaderConstantB(StartRegister, pConstantData, BoolCount); }
HRESULT f_IDirect3DDevice9::GetVertexShaderConstantF(UINT StartRegister, float *pConstantData, UINT Vector4fCount) { return f_pD3DDevice->GetVertexShaderConstantF(StartRegister, pConstantData, Vector4fCount); }
HRESULT f_IDirect3DDevice9::GetVertexShaderConstantI(UINT StartRegister, int *pConstantData, UINT Vector4iCount) { return f_pD3DDevice->GetVertexShaderConstantI(StartRegister, pConstantData, Vector4iCount); }
HRESULT f_IDirect3DDevice9::GetViewport(D3DVIEWPORT9 *pViewport) { return f_pD3DDevice->GetViewport(pViewport); }
float   f_IDirect3DDevice9::GetNPatchMode() { return f_pD3DDevice->GetNPatchMode(); }
HRESULT f_IDirect3DDevice9::LightEnable(DWORD Index, BOOL Enable) { return f_pD3DDevice->LightEnable(Index, Enable); }
HRESULT f_IDirect3DDevice9::MultiplyTransform(D3DTRANSFORMSTATETYPE State, CONST D3DMATRIX *pMatrix) { return f_pD3DDevice->MultiplyTransform(State, pMatrix); }
HRESULT f_IDirect3DDevice9::Present(CONST RECT *pSourceRect, CONST RECT *pDestRect, HWND hDestWindowOverride, CONST RGNDATA *pDirtyRegion) { return f_pD3DDevice->Present(pSourceRect, pDestRect, hDestWindowOverride, pDirtyRegion); }
HRESULT f_IDirect3DDevice9::ProcessVertices(UINT SrcStartIndex, UINT DestIndex, UINT VertexCount, IDirect3DVertexBuffer9 *pDestBuffer, IDirect3DVertexDeclaration9 *pVertexDecl, DWORD Flags) { return f_pD3DDevice->ProcessVertices(SrcStartIndex, DestIndex, VertexCount, pDestBuffer, pVertexDecl, Flags); }
HRESULT f_IDirect3DDevice9::SetClipPlane(DWORD Index, CONST float *pPlane) { return f_pD3DDevice->SetClipPlane(Index, pPlane); }
HRESULT f_IDirect3DDevice9::SetClipStatus(CONST D3DCLIPSTATUS9 *pClipStatus) { return f_pD3DDevice->SetClipStatus(pClipStatus); }
HRESULT f_IDirect3DDevice9::SetCurrentTexturePalette(UINT PaletteNumber) { return f_pD3DDevice->SetCurrentTexturePalette(PaletteNumber); }
void    f_IDirect3DDevice9::SetCursorPosition(int X, int Y, DWORD Flags) { f_pD3DDevice->SetCursorPosition(X, Y, Flags); }
HRESULT f_IDirect3DDevice9::SetCursorProperties(UINT XHotSpot, UINT YHotSpot, IDirect3DSurface9 *pCursorBitmap) { return f_pD3DDevice->SetCursorProperties(XHotSpot, YHotSpot, pCursorBitmap); }
HRESULT f_IDirect3DDevice9::SetDepthStencilSurface(IDirect3DSurface9 *pNewZStencil) { return f_pD3DDevice->SetDepthStencilSurface(pNewZStencil); }
HRESULT f_IDirect3DDevice9::SetDialogBoxMode(BOOL bEnableDialogs) { return f_pD3DDevice->SetDialogBoxMode(bEnableDialogs); }
HRESULT f_IDirect3DDevice9::SetFVF(DWORD FVF) { return f_pD3DDevice->SetFVF(FVF); }
void    f_IDirect3DDevice9::SetGammaRamp(UINT iSwapChain, DWORD Flags, CONST D3DGAMMARAMP *pRamp) { f_pD3DDevice->SetGammaRamp(iSwapChain, Flags, pRamp); }
HRESULT f_IDirect3DDevice9::SetIndices(IDirect3DIndexBuffer9 *pIndexData) { return f_pD3DDevice->SetIndices(pIndexData); }
HRESULT f_IDirect3DDevice9::SetLight(DWORD Index, CONST D3DLIGHT9 *pLight) { return f_pD3DDevice->SetLight(Index, pLight); }
HRESULT f_IDirect3DDevice9::SetMaterial(CONST D3DMATERIAL9 *pMaterial) { return f_pD3DDevice->SetMaterial(pMaterial); }
HRESULT f_IDirect3DDevice9::SetNPatchMode(float nSegments) { return f_pD3DDevice->SetNPatchMode(nSegments); }
HRESULT f_IDirect3DDevice9::SetPaletteEntries(UINT PaletteNumber, CONST PALETTEENTRY *pEntries) { return f_pD3DDevice->SetPaletteEntries(PaletteNumber, pEntries); }
HRESULT f_IDirect3DDevice9::SetPixelShader(IDirect3DPixelShader9 *pShader) { return f_pD3DDevice->SetPixelShader(pShader); }
HRESULT f_IDirect3DDevice9::SetPixelShaderConstantB(UINT StartRegister, CONST BOOL *pConstantData, UINT BoolCount) { return f_pD3DDevice->SetPixelShaderConstantB(StartRegister, pConstantData, BoolCount); }
HRESULT f_IDirect3DDevice9::SetPixelShaderConstantF(UINT StartRegister, CONST float *pConstantData, UINT Vector4fCount) { return f_pD3DDevice->SetPixelShaderConstantF(StartRegister, pConstantData, Vector4fCount); }
HRESULT f_IDirect3DDevice9::SetPixelShaderConstantI(UINT StartRegister, CONST int *pConstantData, UINT Vector4iCount) { return f_pD3DDevice->SetPixelShaderConstantI(StartRegister, pConstantData, Vector4iCount); }
HRESULT f_IDirect3DDevice9::SetRenderState(D3DRENDERSTATETYPE State, DWORD Value) { return f_pD3DDevice->SetRenderState(State, Value); }
HRESULT f_IDirect3DDevice9::SetRenderTarget(DWORD RenderTargetIndex, IDirect3DSurface9 *pRenderTarget) { return f_pD3DDevice->SetRenderTarget(RenderTargetIndex, pRenderTarget); }
HRESULT f_IDirect3DDevice9::SetSamplerState(DWORD Sampler, D3DSAMPLERSTATETYPE Type, DWORD Value) { return f_pD3DDevice->SetSamplerState(Sampler, Type, Value); }
HRESULT f_IDirect3DDevice9::SetScissorRect(CONST RECT *pRect) { return f_pD3DDevice->SetScissorRect(pRect); }
HRESULT f_IDirect3DDevice9::SetSoftwareVertexProcessing(BOOL bSoftware) { return f_pD3DDevice->SetSoftwareVertexProcessing(bSoftware); }
HRESULT f_IDirect3DDevice9::SetStreamSource(UINT StreamNumber, IDirect3DVertexBuffer9 *pStreamData, UINT OffsetInBytes, UINT Stride) { return f_pD3DDevice->SetStreamSource(StreamNumber, pStreamData, OffsetInBytes, Stride); }
HRESULT f_IDirect3DDevice9::SetStreamSourceFreq(UINT StreamNumber, UINT Divider) { return f_pD3DDevice->SetStreamSourceFreq(StreamNumber, Divider); }
HRESULT f_IDirect3DDevice9::SetTexture(DWORD Stage, IDirect3DBaseTexture9 *pTexture) { return f_pD3DDevice->SetTexture(Stage, pTexture); }
HRESULT f_IDirect3DDevice9::SetTextureStageState(DWORD Stage, D3DTEXTURESTAGESTATETYPE Type, DWORD Value) { return f_pD3DDevice->SetTextureStageState(Stage, Type, Value); }
HRESULT f_IDirect3DDevice9::SetTransform(D3DTRANSFORMSTATETYPE State, CONST D3DMATRIX *pMatrix) { return f_pD3DDevice->SetTransform(State, pMatrix); }
HRESULT f_IDirect3DDevice9::SetVertexDeclaration(IDirect3DVertexDeclaration9 *pDecl) { return f_pD3DDevice->SetVertexDeclaration(pDecl); }
HRESULT f_IDirect3DDevice9::SetVertexShader(IDirect3DVertexShader9 *pShader) { return f_pD3DDevice->SetVertexShader(pShader); }
HRESULT f_IDirect3DDevice9::SetVertexShaderConstantB(UINT StartRegister, CONST BOOL *pConstantData, UINT BoolCount) { return f_pD3DDevice->SetVertexShaderConstantB(StartRegister, pConstantData, BoolCount); }
HRESULT f_IDirect3DDevice9::SetVertexShaderConstantF(UINT StartRegister, CONST float *pConstantData, UINT Vector4fCount) { return f_pD3DDevice->SetVertexShaderConstantF(StartRegister, pConstantData, Vector4fCount); }
HRESULT f_IDirect3DDevice9::SetVertexShaderConstantI(UINT StartRegister, CONST int *pConstantData, UINT Vector4iCount) { return f_pD3DDevice->SetVertexShaderConstantI(StartRegister, pConstantData, Vector4iCount); }
HRESULT f_IDirect3DDevice9::SetViewport(CONST D3DVIEWPORT9 *pViewport) { return f_pD3DDevice->SetViewport(pViewport); }
BOOL    f_IDirect3DDevice9::ShowCursor(BOOL bShow) { return f_pD3DDevice->ShowCursor(bShow); }
HRESULT f_IDirect3DDevice9::StretchRect(IDirect3DSurface9 *pSourceSurface, CONST RECT *pSourceRect, IDirect3DSurface9 *pDestSurface, CONST RECT *pDestRect, D3DTEXTUREFILTERTYPE Filter) { return f_pD3DDevice->StretchRect(pSourceSurface, pSourceRect, pDestSurface, pDestRect, Filter); }
HRESULT f_IDirect3DDevice9::TestCooperativeLevel() { return f_pD3DDevice->TestCooperativeLevel(); }
HRESULT f_IDirect3DDevice9::UpdateSurface(IDirect3DSurface9 *pSourceSurface, CONST RECT *pSourceRect, IDirect3DSurface9 *pDestinationSurface, CONST POINT *pDestPoint) { return f_pD3DDevice->UpdateSurface(pSourceSurface, pSourceRect, pDestinationSurface, pDestPoint); }
HRESULT f_IDirect3DDevice9::UpdateTexture(IDirect3DBaseTexture9 *pSourceTexture, IDirect3DBaseTexture9 *pDestinationTexture) { return f_pD3DDevice->UpdateTexture(pSourceTexture, pDestinationTexture); }
HRESULT f_IDirect3DDevice9::ValidateDevice(DWORD *pNumPasses) { return f_pD3DDevice->ValidateDevice(pNumPasses); }
 