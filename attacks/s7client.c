#include <stdio.h>
#include <stdlib.h>
#include <snap7.h>
#include <stdbool.h>
int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("Użycie: %s <PLC_IP>\n", argv[0]);
        return 1;
    }
    const char *ip_plc = argv[1];
    // Utworzenie obiektu klienta Snap7 i implementacja protokolu s7comm
    S7Object klient = Cli_Create();
    if (!klient) {
        printf("Błąd: nie można utworzyć klienta Snap7.\n");
        return 1;
    }
    // Dla S7-1200 standardowa konfiguracja parametrow CPU to rack=0, slot=1
    int rack = 0;
    int slot = 1;
    int res = Cli_ConnectTo(klient, ip_plc, rack, slot);
    if (res != 0) {
        char opis[1024];
        Cli_ErrorText(res, opis, sizeof(opis));
        printf("Błąd połączenia: %d (%s)\n", res, opis);
        Cli_Destroy(&klient);
        return 2;
    }
    printf("OK: Połączono z PLC %s (S7comm/TCP 102)\n", ip_plc);
    // Odczyt statusu CPU (read-only)
    int status = 0;
    res = Cli_GetPlcStatus(klient, &status);
    if (res == 0) {
        printf("Status PLC (kod): %d\n", status);
    } else {
        char opis[1024];
        Cli_ErrorText(res, opis, sizeof(opis));
        printf("Nie udało się pobrać statusu: %d (%s)\n", res, opis);
    }
    Cli_Disconnect(klient);
    Cli_Destroy(&klient);
    printf("Rozłączono.\n");
    return 0;
