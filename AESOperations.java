/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package aes;

import java.util.ArrayList;

/**
 * Clase que contiene las operaciones básicas para llevar a cabo el cifrado simétrico
 * siguiento el estándar AES definido en el FIPS 197
 * @version 1.0
 * @author Oscar Lemus
 */
public class AESOperations {
    
    private ArrayList<ArrayList<Byte>> matrizMC;
    private ArrayList<ArrayList<Byte>> sBox;
    private ArrayList<ArrayList<ArrayList<Byte>>> keySchedule;
    
    /**
     * Constructor de la clase, cuando se instancia se inicializa la matriz
     * utilizada en la operación de Mix Column y se inicializa la S-Box para cifrado
     * @param key Clave para cifrado
     */
    public AESOperations(ArrayList<ArrayList<Byte>> key) {
        initMC();
        initSBox();
        keySchedule = new ArrayList<>();
        keySchedule(key);
    }
    
    /**
     * Ejecuta el cifrado de la matriz recibida, realiza los ciclos definidos 
     * en el estándar.
     * @param mat Matriz a cifrar
     */
    public void cipher(ArrayList<ArrayList<Byte>> mat) {
        xorMat(mat, keySchedule.get(0));
        for (int i = 1; i<=9; i++) {
            subBytes(mat);
            shiftRows(mat);
            mixColumns(mat);
            xorMat(mat, keySchedule.get(i));
        }
        subBytes(mat);
        shiftRows(mat);
        xorMat(mat, keySchedule.get(10));
    }
    
    /**
     * Método que cambia los bytes de la matriz de acuerdo a la S-Box
     * @param mat Matriz a realizar la operación de subBytes
     */
    private void subBytes (ArrayList<ArrayList<Byte>> mat) {
        for (int i = 0; i < mat.size(); i++) {
            subByte(mat.get(i));
        }
    }
    
    /**
     * Método que realiza el corriemiento de las filas de acuerdo a la
     * operación de shift rows definida en el estándar.
     * @param mat Matriz a realizar la operación
     */
    private void shiftRows(ArrayList<ArrayList<Byte>> mat) {
        
        ArrayList<ArrayList<Byte>> aux = new ArrayList<>();
        
        ArrayList<Byte> auxShift = new ArrayList<>();
        auxShift.add(mat.get(0).get(0));
        auxShift.add(mat.get(1).get(1));
        auxShift.add(mat.get(2).get(2));
        auxShift.add(mat.get(3).get(3));
        aux.add(auxShift);
        
        auxShift = new ArrayList<>();
        auxShift.add(mat.get(1).get(0));
        auxShift.add(mat.get(2).get(1));
        auxShift.add(mat.get(3).get(2));
        auxShift.add(mat.get(0).get(3));
        aux.add(auxShift);
        
        auxShift = new ArrayList<>();
        auxShift.add(mat.get(2).get(0));
        auxShift.add(mat.get(3).get(1));
        auxShift.add(mat.get(0).get(2));
        auxShift.add(mat.get(1).get(3));
        aux.add(auxShift);
        
        auxShift = new ArrayList<>();
        auxShift.add(mat.get(3).get(0));
        auxShift.add(mat.get(0).get(1));
        auxShift.add(mat.get(1).get(2));
        auxShift.add(mat.get(2).get(3));
        aux.add(auxShift);
        
        mat.set(0, aux.get(0));
        mat.set(1, aux.get(1));
        mat.set(2, aux.get(2));
        mat.set(3, aux.get(3));
        
    }
    
    /**
     * Método que realiza la operación mixColumn de acuerdo al estándar
     * @param mat Matriz a multiplicar.
     */
    private void mixColumns(ArrayList<ArrayList<Byte>> mat) {
        
        for (int i = 0; i<4; i++) {
            mat.set(i, multiplyC(mat.get(i)));
        }
        
    }
    
    /**
     * Método que se encarga de generar el key schedule de la clave dada en el
     * constructor, genera las subclaves a utilizar en el proceso de cifrado
     * @param key Clave base de la cual se basa para generar las subclaves
     */
    private void keySchedule(ArrayList<ArrayList<Byte>> key) {
        ArrayList<ArrayList<Byte>> keyAux = new ArrayList<>();
        ArrayList<Byte> auxC;
        ArrayList<Byte> rCon = new ArrayList<>();
        rCon.add((byte) 0x01);
        rCon.add((byte) 0x00);
        rCon.add((byte) 0x00);
        rCon.add((byte) 0x00);
        
        keySchedule.add(key);
        for (int i = 0; i<10; i++) {
            keyAux = new ArrayList<>();
            auxC = new ArrayList<>();
            if (i<8)
                rCon.set(0, (byte) (0x01<<i));
            else if (i == 8)
                rCon.set(0, (byte) (0x1b));
            else
                rCon.set(0, (byte) (0x36));
            
            copyColumn(keySchedule.get(i).get(3), auxC);
            rotWord(auxC);
            subByte(auxC);
            xorColumns(auxC, rCon);
            
            xorColumns(auxC, keySchedule.get(i).get(0));
            keyAux.add(auxC);
            
            for (int j = 1; j<4; j++) {
                auxC = new ArrayList<>();
                copyColumn(keyAux.get(j-1), auxC);
                xorColumns(auxC, keySchedule.get(i).get(j));
                keyAux.add(auxC);
            }
            keySchedule.add(keyAux);
            
        }
    }
    
    /**
     * Realiza el producto de una columna con la matriz de acuerdo a la 
     * operación de mix column.
     * @param values Columna a multiplicar
     * @return Columna con los valores resultantes del producto
     */
    private ArrayList<Byte> multiplyC (ArrayList<Byte> values) {
        ArrayList<Byte> regreso = new ArrayList<>();
        byte aux;
        for (int i = 0; i<4; i++) {
            aux = (byte) 0x00;
            for (int j = 0; j<4; j++) {
                aux = (byte) (aux ^ multiply(values.get(j), matrizMC.get(i).get(j)));
            }
            regreso.add(aux);
        }
        
        return regreso;
    }
    
    /**
     * Operación definida para llevar a cabo el producto de dos bytes
     * siguiendo el algoritmo XTIME
     * @param a Primer byte involucrado en el producto
     * @param b Segundo byte involucrado en el producto
     * @return Byte resultante del producto
     */
    private byte multiply(byte a, byte b) {
        byte res = (byte) 0x00;
        byte aux = (byte) 0x80;
        byte div = (byte) 0x1b;

        String auxs = Integer.toBinaryString(Byte.toUnsignedInt(b));
        
        if (auxs.charAt(auxs.length()-1) == '1')
            res = (byte) (res ^ a);
        
        for (int i = auxs.length()-2; i>=0; i--) {
            if ((aux & a) == ((byte) 0x80)) {
                a = (byte) (a << 1);
                a = (byte) (a ^ div);
            }
            else
                a = (byte) (a << 1);
            if (auxs.charAt(i) == '1')
                res = (byte) (res ^ a);
        }
        return res;
    }
    
    /**
     * Método encargado de inicializar la matriz con la cual se lleva a cabo 
     * la operación de mix column
     */
    private void initMC() {
        matrizMC = new ArrayList<>();
        ArrayList<Byte> aux = new ArrayList<>();
        
        aux.add((byte) 0x02);
        aux.add((byte) 0x03);
        aux.add((byte) 0x01);
        aux.add((byte) 0x01);
        
        matrizMC.add(aux);
        
        aux = new ArrayList<>();
        aux.add((byte) 0x01);
        aux.add((byte) 0x02);
        aux.add((byte) 0x03);
        aux.add((byte) 0x01);
        
        matrizMC.add(aux);
        
        aux = new ArrayList<>();
        aux.add((byte) 0x01);
        aux.add((byte) 0x01);
        aux.add((byte) 0x02);
        aux.add((byte) 0x03);
        
        matrizMC.add(aux);
        
        aux = new ArrayList<>();
        aux.add((byte) 0x03);
        aux.add((byte) 0x01);
        aux.add((byte) 0x01);
        aux.add((byte) 0x02);
        
        matrizMC.add(aux);
    }
    
    /**
     * Método encargado de inicializar la matriz que almacena los valores
     * de la S-Box con la cuál se lleva a cabo la operación de sub bytes
     */
    private void initSBox() {
        ArrayList<Byte> aux;
        sBox = new ArrayList<>();
        
        aux = new ArrayList<>();
        aux.add((byte) 0x63);
        aux.add((byte) 0xca);
        aux.add((byte) 0xb7);
        aux.add((byte) 0x04);
        aux.add((byte) 0x09);
        aux.add((byte) 0x53);
        aux.add((byte) 0xd0);
        aux.add((byte) 0x51);
        aux.add((byte) 0xcd);
        aux.add((byte) 0x60);
        aux.add((byte) 0xe0);
        aux.add((byte) 0xe7);
        aux.add((byte) 0xba);
        aux.add((byte) 0x70);
        aux.add((byte) 0xe1);
        aux.add((byte) 0x8c);
        sBox.add(aux);
        
        aux = new ArrayList<>();
        aux.add((byte) 0x7c);
        aux.add((byte) 0x82);
        aux.add((byte) 0xfd);
        aux.add((byte) 0xc7);
        aux.add((byte) 0x83);
        aux.add((byte) 0xd1);
        aux.add((byte) 0xef);
        aux.add((byte) 0xa3);
        aux.add((byte) 0x0c);
        aux.add((byte) 0x81);
        aux.add((byte) 0x32);
        aux.add((byte) 0xc8);
        aux.add((byte) 0x78);
        aux.add((byte) 0x3e);
        aux.add((byte) 0xf8);
        aux.add((byte) 0xa1);
        sBox.add(aux);
        
        aux = new ArrayList<>();
        aux.add((byte) 0x77);
        aux.add((byte) 0xc9);
        aux.add((byte) 0x93);
        aux.add((byte) 0x23);
        aux.add((byte) 0x2c);
        aux.add((byte) 0x00);
        aux.add((byte) 0xaa);
        aux.add((byte) 0x40);
        aux.add((byte) 0x13);
        aux.add((byte) 0x4f);
        aux.add((byte) 0x3a);
        aux.add((byte) 0x37);
        aux.add((byte) 0x25);
        aux.add((byte) 0xb5);
        aux.add((byte) 0x98);
        aux.add((byte) 0x89);
        sBox.add(aux);
        
        aux = new ArrayList<>();
        aux.add((byte) 0x7b);
        aux.add((byte) 0x7d);
        aux.add((byte) 0x26);
        aux.add((byte) 0xc3);
        aux.add((byte) 0x1a);
        aux.add((byte) 0xed);
        aux.add((byte) 0xfb);
        aux.add((byte) 0x8f);
        aux.add((byte) 0xec);
        aux.add((byte) 0xdc);
        aux.add((byte) 0x0a);
        aux.add((byte) 0x6d);
        aux.add((byte) 0x2e);
        aux.add((byte) 0x66);
        aux.add((byte) 0x11);
        aux.add((byte) 0x0d);
        sBox.add(aux);
        
        aux = new ArrayList<>();
        aux.add((byte) 0xf2);
        aux.add((byte) 0xfa);
        aux.add((byte) 0x36);
        aux.add((byte) 0x18);
        aux.add((byte) 0x1b);
        aux.add((byte) 0x20);
        aux.add((byte) 0x43);
        aux.add((byte) 0x92);
        aux.add((byte) 0x5f);
        aux.add((byte) 0x22);
        aux.add((byte) 0x49);
        aux.add((byte) 0x8d);
        aux.add((byte) 0x1c);
        aux.add((byte) 0x48);
        aux.add((byte) 0x69);
        aux.add((byte) 0xbf);
        sBox.add(aux);
        
        aux = new ArrayList<>();
        aux.add((byte) 0x6b);
        aux.add((byte) 0x59);
        aux.add((byte) 0x3f);
        aux.add((byte) 0x96);
        aux.add((byte) 0x6e);
        aux.add((byte) 0xfc);
        aux.add((byte) 0x4d);
        aux.add((byte) 0x9d);
        aux.add((byte) 0x97);
        aux.add((byte) 0x2a);
        aux.add((byte) 0x06);
        aux.add((byte) 0xd5);
        aux.add((byte) 0xa6);
        aux.add((byte) 0x03);
        aux.add((byte) 0xd9);
        aux.add((byte) 0xe6);
        sBox.add(aux);
        
        aux = new ArrayList<>();
        aux.add((byte) 0x6f);
        aux.add((byte) 0x47);
        aux.add((byte) 0xf7);
        aux.add((byte) 0x05);
        aux.add((byte) 0x5a);
        aux.add((byte) 0xb1);
        aux.add((byte) 0x33);
        aux.add((byte) 0x38);
        aux.add((byte) 0x44);
        aux.add((byte) 0x90);
        aux.add((byte) 0x24);
        aux.add((byte) 0x4e);
        aux.add((byte) 0xb4);
        aux.add((byte) 0xf6);
        aux.add((byte) 0x8e);
        aux.add((byte) 0x42);
        sBox.add(aux);
        
        aux = new ArrayList<>();
        aux.add((byte) 0xc5);
        aux.add((byte) 0xf0);
        aux.add((byte) 0xcc);
        aux.add((byte) 0x9a);
        aux.add((byte) 0xa0);
        aux.add((byte) 0x5b);
        aux.add((byte) 0x85);
        aux.add((byte) 0xf5);
        aux.add((byte) 0x17);
        aux.add((byte) 0x88);
        aux.add((byte) 0x5c);
        aux.add((byte) 0xa9);
        aux.add((byte) 0xc6);
        aux.add((byte) 0x0e);
        aux.add((byte) 0x94);
        aux.add((byte) 0x68);
        sBox.add(aux);
        
        aux = new ArrayList<>();
        aux.add((byte) 0x30);
        aux.add((byte) 0xad);
        aux.add((byte) 0x34);
        aux.add((byte) 0x07);
        aux.add((byte) 0x52);
        aux.add((byte) 0x6a);
        aux.add((byte) 0x45);
        aux.add((byte) 0xbc);
        aux.add((byte) 0xc4);
        aux.add((byte) 0x46);
        aux.add((byte) 0xc2);
        aux.add((byte) 0x6c);
        aux.add((byte) 0xe8);
        aux.add((byte) 0x61);
        aux.add((byte) 0x9b);
        aux.add((byte) 0x41);
        sBox.add(aux);
        
        aux = new ArrayList<>();
        aux.add((byte) 0x01);
        aux.add((byte) 0xd4);
        aux.add((byte) 0xa5);
        aux.add((byte) 0x12);
        aux.add((byte) 0x3b);
        aux.add((byte) 0xcb);
        aux.add((byte) 0xf9);
        aux.add((byte) 0xb6);
        aux.add((byte) 0xa7);
        aux.add((byte) 0xee);
        aux.add((byte) 0xd3);
        aux.add((byte) 0x56);
        aux.add((byte) 0xdd);
        aux.add((byte) 0x35);
        aux.add((byte) 0x1e);
        aux.add((byte) 0x99);
        sBox.add(aux);
        
        aux = new ArrayList<>();
        aux.add((byte) 0x67);
        aux.add((byte) 0xa2);
        aux.add((byte) 0xe5);
        aux.add((byte) 0x80);
        aux.add((byte) 0xd6);
        aux.add((byte) 0xbe);
        aux.add((byte) 0x02);
        aux.add((byte) 0xda);
        aux.add((byte) 0x7e);
        aux.add((byte) 0xb8);
        aux.add((byte) 0xac);
        aux.add((byte) 0xf4);
        aux.add((byte) 0x74);
        aux.add((byte) 0x57);
        aux.add((byte) 0x87);
        aux.add((byte) 0x2d);
        sBox.add(aux);
        
        aux = new ArrayList<>();
        aux.add((byte) 0x2b);
        aux.add((byte) 0xaf);
        aux.add((byte) 0xf1);
        aux.add((byte) 0xe2);
        aux.add((byte) 0xb3);
        aux.add((byte) 0x39);
        aux.add((byte) 0x7f);
        aux.add((byte) 0x21);
        aux.add((byte) 0x3d);
        aux.add((byte) 0x14);
        aux.add((byte) 0x62);
        aux.add((byte) 0xea);
        aux.add((byte) 0x1f);
        aux.add((byte) 0xb9);
        aux.add((byte) 0xe9);
        aux.add((byte) 0x0f);
        sBox.add(aux);
        
        aux = new ArrayList<>();
        aux.add((byte) 0xfe);
        aux.add((byte) 0x9c);
        aux.add((byte) 0x71);
        aux.add((byte) 0xeb);
        aux.add((byte) 0x29);
        aux.add((byte) 0x4a);
        aux.add((byte) 0x50);
        aux.add((byte) 0x10);
        aux.add((byte) 0x64);
        aux.add((byte) 0xde);
        aux.add((byte) 0x91);
        aux.add((byte) 0x65);
        aux.add((byte) 0x4b);
        aux.add((byte) 0x86);
        aux.add((byte) 0xce);
        aux.add((byte) 0xb0);
        sBox.add(aux);
        
        aux = new ArrayList<>();
        aux.add((byte) 0xd7);
        aux.add((byte) 0xa4);
        aux.add((byte) 0xd8);
        aux.add((byte) 0x27);
        aux.add((byte) 0xe3);
        aux.add((byte) 0x4c);
        aux.add((byte) 0x3c);
        aux.add((byte) 0xff);
        aux.add((byte) 0x5d);
        aux.add((byte) 0x5e);
        aux.add((byte) 0x95);
        aux.add((byte) 0x7a);
        aux.add((byte) 0xbd);
        aux.add((byte) 0xc1);
        aux.add((byte) 0x55);
        aux.add((byte) 0x54);
        sBox.add(aux);
        
        aux = new ArrayList<>();
        aux.add((byte) 0xab);
        aux.add((byte) 0x72);
        aux.add((byte) 0x31);
        aux.add((byte) 0xb2);
        aux.add((byte) 0x2f);
        aux.add((byte) 0x58);
        aux.add((byte) 0x9f);
        aux.add((byte) 0xf3);
        aux.add((byte) 0x19);
        aux.add((byte) 0x0b);
        aux.add((byte) 0xe4);
        aux.add((byte) 0xae);
        aux.add((byte) 0x8b);
        aux.add((byte) 0x1d);
        aux.add((byte) 0x28);
        aux.add((byte) 0xbb);
        sBox.add(aux);
        
        aux = new ArrayList<>();
        aux.add((byte) 0x76);
        aux.add((byte) 0xc0);
        aux.add((byte) 0x15);
        aux.add((byte) 0x75);
        aux.add((byte) 0x84);
        aux.add((byte) 0xcf);
        aux.add((byte) 0xa8);
        aux.add((byte) 0xd2);
        aux.add((byte) 0x73);
        aux.add((byte) 0xdb);
        aux.add((byte) 0x79);
        aux.add((byte) 0x08);
        aux.add((byte) 0x8a);
        aux.add((byte) 0x9e);
        aux.add((byte) 0xdf);
        aux.add((byte) 0x16);
        sBox.add(aux);
        
    }
    
    /**
     * Realiza la sustitución de bytes de una determinada columna de acuerdo a la
     * S-Box
     * @param column columna a sustituir
     */
    private void subByte(ArrayList<Byte> column) {
        for (int i = 0; i<column.size(); i++) {
            column.set(i, sBox.get(column.get(i) & 0x0f).get((column.get(i) & 0xf0)>>4));
        }
    }
    
    /**
     * Lleva a cabo la roación de palabra, el primer elemento de la columna
     * lo coloca al final y lleva a cabo el corrimiento
     * @param column 
     */
    private void rotWord(ArrayList<Byte> column) {
        byte aux = column.get(0);
        column.remove(0);
        column.add(aux);
    }
    
    /**
     * Método encargado de copiar una columna en otra.
     * @param column Columna a copiar
     * @param column2cp Columna destino
     */
    private void copyColumn(ArrayList<Byte> column, ArrayList<Byte> column2cp) {
        for (int i = 0; i<column.size(); i++)
            column2cp.add(column.get(i));
    }
    
    /**
     * Lleva a cabo la operación XOR entre dos columnas.
     * @param column Columna involucrada en la operación y donde se almacenará
     * el resultado
     * @param column2 Columna involucrada en la operación 
     */
    private void xorColumns(ArrayList<Byte> column, ArrayList<Byte> column2) {
        for (int i = 0; i<column.size(); i++)
            column.set(i, (byte)(column.get(i) ^ column2.get(i)));
    }
    
    /**
     * Lleva a cabo la operación XOR entre dos matrices
     * @param mat Matriz involucrada en la operación y donde se almacenará
     * el resultado
     * @param mat2 Columna involucrada en la operación 
     */
    private void xorMat(ArrayList<ArrayList<Byte>> mat, ArrayList<ArrayList<Byte>> mat2) {
        for (int i = 0; i<mat.size(); i++) {
            xorColumns(mat.get(i), mat2.get(i));
        }
    }
    
    /**
     * Método encargado de imprimir en pantalla la matriz recibida
     * @param mat Matriz a imprimir
     */
    public void printMat(ArrayList<ArrayList<Byte>> mat) {
        for(int i = 0; i<mat.size(); i++) {
            System.out.println("");
            for (int j=0; j<mat.get(0).size(); j++) {
                System.out.print("\t" + Integer.toHexString(Byte.toUnsignedInt(mat.get(j).get(i))));
            }
        }
        System.out.println();
    }
    
}
