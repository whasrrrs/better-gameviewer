#include <print>

#include <blook/blook.h>
#include <winuser.h>

#include "Windows.h"
#include "blook/misc.h"
#include "blook/process.h"

void open_console() {
    AllocConsole();
    freopen("CONOUT$", "w", stdout);
}

HOOKPROC keyboard_hook_addr = nullptr;
HOOKPROC mouse_hook_addr = nullptr;

void entry() {
    open_console();
    blook::misc::install_optimize_dll_hijacking("HID.dll");

    auto self = blook::Process::self();
    if (auto user32 = self->module("User32.dll").value()) {
        auto SetWindowsHookExW_proc = user32->exports("SetWindowsHookExW").value();
        auto SetWindowsHookExW_hook = SetWindowsHookExW_proc.inline_hook();

        SetWindowsHookExW_hook->install([=](int idHook, HOOKPROC lpfn, HINSTANCE hMod, DWORD dwThreadId) -> HHOOK {
            if (idHook == WH_KEYBOARD_LL) {
                keyboard_hook_addr = lpfn;
                std::println("Captured keyboard hook address: {}", (void *) keyboard_hook_addr);
            } else if (idHook == WH_MOUSE_LL) {
                mouse_hook_addr = lpfn;
                std::println("Captured mouse hook address: {}", (void *) mouse_hook_addr);
            } else {
                return SetWindowsHookExW_hook->call_trampoline<HHOOK>(idHook, lpfn, hMod, dwThreadId);
            }

            return (HHOOK) 0x1234;
        });

        auto TranslateMessage_proc = user32->exports("TranslateMessage").value();
        auto TranslateMessage_hook = TranslateMessage_proc.inline_hook();
        TranslateMessage_hook->install([=](MSG *lpMsg) -> BOOL {
            if (lpMsg) {
                if (lpMsg->message == WM_KEYDOWN || lpMsg->message == WM_KEYUP) {
                    std::println("Keyboard message: {} {}", lpMsg->message, lpMsg->wParam);

                    KBDLLHOOKSTRUCT info{
                            .vkCode = (DWORD) lpMsg->wParam,
                            .scanCode = 0,
                            .flags = static_cast<DWORD>((lpMsg->message == WM_KEYUP) ? LLKHF_UP : 0),
                            .time = 0,
                            .dwExtraInfo = 0};

                    keyboard_hook_addr(1, lpMsg->message, (LPARAM) &info);
                } else if (lpMsg->message == WM_MBUTTONDBLCLK || lpMsg->message == WM_LBUTTONDBLCLK ||
                           lpMsg->message == WM_RBUTTONDBLCLK) {
                    // Convert to DOWN message
                    // 0x203 -> 0x201
                    // 0x206 -> 0x204
                    // 0x209 -> 0x207
                    lpMsg->message -= 2;
                }
            }
            return TranslateMessage_hook->call_trampoline<BOOL>(lpMsg);
        });
    }
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            entry();
            break;
    }
    return TRUE;
}