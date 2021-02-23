# ModeladoFasesCiberAtaques
Repositorio de mi trabajo de fin de grado.

La carpeta **SCRIPTS** contiene:
   - Script python que lee del log de snort e inserta en mongodb 
   - Ficheros json de prueba
   
La carpeta **pcaps** contiene:
   - Listado de web de pcaps con y sin ataques para poder probar que funciona el sistema.
   
**Hyperalert.py** es el script que realiza las consultas a mongo db para realizar la correlación de alertas, eventos, flujos y clasificacion de flujos. Tiene las salidas por consola y un menu en la terminal para acceder a los datos.

**Controlador.py** es el hyperalert.py pero sin salidas por consola, modificado para adaptarlo al desarrollo de una arquitectura modelo vista controlador. Este realiza las consultas a la base de datos y tiene las funciones necesarias para formatear los datos para devolverlos a la vista.

**vista.py** es un pequeño ejemplo de interfaz gráfico para obtener los datos del sistema de una forma mas visual.
