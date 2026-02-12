# Laboratorio 2 - Ciberseguridad

## Miembros del grupo

| Nombre             | Código    | Correo electrónico           |
|--------------------|-----------|------------------------------|
| Adrian Velasquez   | 202222737 | a.velasquezs@uniandes.edu.co |
| Andres Botero Ruiz | 202223503 | a.boteror@uniandes.edu.co    |
| Sergio Castaño     | 202310390 | sa.castanoa1@uniandes.edu.co |

## Descripción del laboratorio

En este repositorio se encuentra el código del algoritmo AES-128 para encriptar y desencriptar archivos.  
En general, se utilizó el paquete `pycryptodome` para implementar la solución.  

## Uso del código

Antes de empezar, es necesario crear un archivo `k.key` con el generador de claves (16 bits).

```zsh
python3 key_gen.py
```

Una vez hecho esto, en el root del proyecto encontrará el archivo `k.key` con la clave generada.

Para encriptar o desencriptar un archivo, se debe ejecutar el siguiente comando:

```zsh
python3 aes.py <modo> <archivo> <llave>
```

Donde `<modo>` es el modo de operación a utilizar (e o d, para encriptar o desencriptar respectivamente), 
`<archivo>` es la ruta al archivo a encriptar/desencriptar y `<llave>` es la ruta a la llave de 16 bits (en este caso, `k.key`).

El resultado de la encriptación se guardará en un archivo con el mismo nombre que el archivo a encriptar pero con un prefijo `enc_`. 
Por ejemplo, si el archivo a encriptar es `archivo.txt`, el resultado se guardará en `enc_archivo.txt`.

## Ejemplo de uso

Asumiendo que se está corriendo desde `~/`, y que el archivo a encriptar se encuentra en `~/in.txt`, el comando para encriptar el archivo sería:


### Generar una llave
```zsh
python3 key_gen.py
```
El resultado es un archivo binario de 16 bytes y se guardará en `~/k.key`.


### Encriptar un archivo
```zsh
python3 aes.py e ~/in.txt ~/k.key
```

### Desencriptar un archivo
```zsh
python3 aes.py d ~/enc_in.txt ~/k.key
```