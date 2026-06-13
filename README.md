
**Windows Defender Está Siendo Usado para Hackear Windows**


**Un exploit de tipo zero-day llamado *BlueHammer* explota el proceso de actualización de Defender para otorgar a los atacantes acceso completo *SYSTEM***
<img width="956" height="630" alt="image" src="https://github.com/user-attachments/assets/6683379e-505d-4f37-8c77-3ec14798dd11" />

---

## 📌 Descripción General

Windows Defender, el antivirus integrado en todas las máquinas con Windows, tiene un **exploit de tipo zero-day** con código fuente completo disponible en GitHub. **No hay parche, no hay CVE y está confirmado que funciona en Windows 10 y 11 completamente actualizados**. Un investigador, que afirma que Microsoft incumplió su palabra, ha proporcionado a cualquier atacante con un simple privilegio de escalada que lleva cuentas con bajos privilegios directamente a **`NT AUTHORITY\SYSTEM`**. En Windows Server, el resultado es diferente pero igualmente grave: un usuario estándar obtiene acceso de administrador elevado. 😏

---

## 🔍 ¿Qué es *BlueHammer*?

- **Nombre del exploit**: *BlueHammer*
- **Fecha de publicación**: 2 de abril (divulgación pública) y 3 de abril (código fuente en GitHub)
- **Investigador**: Publicado bajo el alias **Chaotic Eclipse** (también conocido como *Nightmare Eclipse*)
- **Mensaje a Microsoft**: *"Os dije que esto pasaría"*

### 📜 Contexto del investigador

En **finales de marzo**, el mismo investigador abrió un blog con una sola publicación explicando que **nunca quiso volver a la investigación pública**. Alguien había hecho un acuerdo con él y luego lo rompió, sabiendo exactamente cuáles serían las consecuencias. La publicación dice que lo dejó sin hogar y sin nada. Una semana después, *BlueHammer* se hizo público en GitHub con un mensaje que **agradece específicamente al liderazgo del MSRC por hacerlo necesario**. Esto no es alguien molesto por un proceso de revisión lento, sino alguien que **no tiene nada más que perder**.

---

## 🛠️ ¿Cómo funciona el exploit?

*BlueHammer* **no es un error tradicional**. No necesita shellcode, corrupción de memoria ni exploits en el kernel para funcionar. En su lugar, **encadena cinco componentes legítimos de Windows** en una secuencia que produce algo que sus diseñadores nunca pretendieron. Estos componentes son:

1. **Windows Defender**
2. **Servicio de Copias de Sombra de Volumen (VSS)**
3. **API de Archivos en la Nube**
4. **Bloqueos oportunistas**
5. **Interfaz RPC interna de Defender**

📌 **Limitación práctica**: El exploit necesita una **actualización pendiente de firmas de Defender** disponible en el momento del ataque. Sin una en cola, la cadena no se activa. Esto lo hace menos confiable que un exploit de "botón único", pero **no lo hace seguro de ignorar**.

---

## 🔗 Cadena de ataque paso a paso

1. **Windows Defender** actualiza sus definiciones de antivirus.
   - Parte del proceso implica crear una **copia de sombra de volumen temporal** (VSS), el mismo mecanismo que Windows usa para copias de seguridad y restauración.
   - Esta copia contiene archivos normalmente bloqueados durante el funcionamiento regular, incluyendo la **base de datos SAM**, que almacena los hashes de contraseñas de todas las cuentas locales.

2. **BlueHammer** se registra como un proveedor de sincronización de archivos en la nube (similar a OneDrive o Dropbox).
   - Cuando Defender toca un archivo específico dentro de esa carpeta, el exploit recibe una llamada de retorno y **coloca inmediatamente un bloqueo oportunista** en ese archivo.
   - Defender se congela, bloqueado y esperando una respuesta que nunca llega. **La copia de sombra sigue montada**.

3. Con Defender inmóvil, el exploit **lee los archivos de registro SAM, SYSTEM y SECURITY** directamente de la copia de sombra.
   - Descifra los hashes de contraseñas NTLM almacenados usando la clave de arranque extraída del archivo SYSTEM.
   - Cambia la contraseña de una cuenta de administrador local, inicia sesión con esa cuenta, copia el token de seguridad del administrador y **lo eleva al nivel SYSTEM**.
   - Crea un servicio temporal de Windows y lanza un símbolo del sistema ejecutándose como **`NT AUTHORITY\SYSTEM`**.
   - Para cubrir sus huellas, **restablece el hash original de la contraseña**. La contraseña de la cuenta local parece completamente sin cambios. **No hay alertas, ni caídas, ni nada**.

⏱️ **Todo el proceso se ejecuta en menos de un minuto** desde una sesión de usuario normal.

---
## 💥 Mensajes en el código

- El nombre del proveedor de archivos en la nube en el código fuente del exploit está codificado como **`IHATEMICROSOFT`**.
- La contraseña de administrador utilizada durante la escalada está codificada como **`$PWNed666!!!WDFAIL`**.

🔥 **Estos no son errores dejados por accidente**. Son mensajes escritos directamente en el código y **solo hay un lector pretendido**.

---
## ✅ Confirmación de la amenaza

- **Will Dormann**, analista principal de vulnerabilidades en Tharros, probó el exploit y confirmó que funciona lo suficientemente bien como para ser una amenaza real.
- **Microsoft ha estado recortando costos**. Analistas experimentados que sabían cómo examinar un exploit complejo y entenderlo han sido reemplazados por personal que sigue listas de verificación de procesos rígidos. Una de esas listas de verificación requiere una **demostración en video del exploit**. Investigadores que se niegan a hacer un video tienen sus informes cerrados. Dormann dijo en Mastodon que no le sorprendería si Microsoft cerrara el caso porque el investigador se negó a enviar un video, ya que aparentemente se ha convertido en un requisito del MSRC.

---
## 🚨 Respuesta de Microsoft

Microsoft respondió a *BlueHammer* con una declaración sobre **apoyar la divulgación coordinada de vulnerabilidades**.

💬 *"Tomémonos un momento con esto. El punto de esta situación es que el propio proceso de Microsoft rompió la coordinación. Responder a esto diciendo que apoyas la coordinación no es una respuesta."*

---
## 🔒 ¿Es suficiente la detección de Defender?

Microsoft lanzó una actualización de firmas de Defender que detecta el binario original de *BlueHammer* como **`Exploit:Win32/DfndrPEBluHmr.BB`**.

⚠️ **Esta firma NO arregla la vulnerabilidad**. Solo detecta la muestra compilada del código fuente publicado. Si se recompila el mismo código con un pequeño cambio, Defender **no lo detecta en absoluto**. La detección solo captura ese archivo específico. **La técnica en sí, que se ejecuta completamente a través de componentes normales de Windows haciendo exactamente lo que fueron diseñados para hacer, sigue completamente indetectable**.

➡️ **Hasta que Microsoft arregle la causa raíz, una firma no es protección.**

---
## 🧪 Pruebas independientes

El equipo de investigación **Howler Cell** en Cyderes arregló los errores en el PoC original y ejecutó el exploit completo en Windows 10 y 11 parcheados. **Funciona**. Shell SYSTEM desde una sesión de usuario restringido en menos de un minuto.

---
## 📢 Estado actual

- **CVE asignado CVE-2026-33825**
- **No hay parche disponible**
- *CVSS	~7.8*
- El código del exploit es público
- El repositorio de GitHub ya tiene más de **100 forks y casi 300 estrellas**
- Múltiples investigadores han arreglado los errores originales y confirmado que funciona
- Los grupos de ransomware y actores de APT tienden a recoger código público de escalada de privilegios y ponerlo en uso **dentro de días** de que esté disponible.

---
## 🚨 ¿Qué hacer AHORA?

### 🔍 Monitoreo y alertas

→ **Monitorear enumeraciones VSS** provenientes de procesos de usuario regulares.
   - Llamadas a `NtQueryDirectoryObject` dirigidas a objetos `HarddiskVolumeShadowCopy` desde fuera de herramientas de respaldo o del sistema es una **bandera roja** con casi ninguna explicación inocente.

→ **Vigilar registros de raíces de sincronización de archivos en la nube** por procesos desconocidos.
   - `CfRegisterSyncRoot` siendo llamado desde algo que no sea OneDrive, Dropbox o Box vale la pena de verificar inmediatamente. Esa llamada es exactamente cómo *BlueHammer* configura su trampa.

→ **Alertar sobre procesos con bajos privilegios creando servicios de Windows o agarrando tokens a nivel SYSTEM**.
   - *BlueHammer* usa `CreateService` para registrar brevemente un servicio malicioso durante la escalada, y eso aparece en la telemetría de EDR.

→ **Vigilar cambios rápidos de contraseña** en cuentas de administrador local.
   - *BlueHammer* restablece la contraseña, la usa y luego la restablece de vuelta. Eventos de seguridad con IDs **4723** y **4724** disparándose dos veces en rápida sucesión en la misma cuenta **no tienen una explicación normal**.

→ **Mantener permisos ajustados**.
   - *BlueHammer* necesita una sesión local para ejecutarse, por lo que cada permiso que un usuario estándar no necesita realmente es **superficie de ataque que puede ser eliminada**.

→ **Seguir atentamente los boletines de seguridad de Microsoft**.
   - Cuando llegue un parche, trátalo como **alta prioridad**.


