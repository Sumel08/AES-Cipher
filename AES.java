/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package aes;

import java.util.ArrayList;

/**
 * Clase para testear el funcionamiento de las operaciones definidas en la clase
 * AESOperations
 * @author Oscar Lemus
 */
public class AES {

    public static void main(String[] args) {
        // TODO Auto-generated method stub

        ArrayList<ArrayList<Byte>> mat = new ArrayList<>();
        ArrayList<ArrayList<Byte>> key = new ArrayList<>();
        ArrayList<Byte> ini;
        
        /*
        inicia la matriz a cifrar
        */
        
        ini = new ArrayList<>();
        ini.add((byte) 0x32);
        ini.add((byte) 0x43);
        ini.add((byte) 0xf6);
        ini.add((byte) 0xa8);
        
        mat.add(ini);
        
        ini = new ArrayList<>();
        ini.add((byte) 0x88);
        ini.add((byte) 0x5a);
        ini.add((byte) 0x30);
        ini.add((byte) 0x8d);
        
        mat.add(ini);
        
        ini = new ArrayList<>();
        ini.add((byte) 0x31);
        ini.add((byte) 0x31);
        ini.add((byte) 0x98);
        ini.add((byte) 0xa2);
        
        mat.add(ini);
        
        ini = new ArrayList<>();
        ini.add((byte) 0xe0);
        ini.add((byte) 0x37);
        ini.add((byte) 0x07);
        ini.add((byte) 0x34);
        
        mat.add(ini);
        
        /*
        Inicia la matriz que almacena la clave
        */
        
        ini = new ArrayList<>();
        ini.add((byte) 0x2b);
        ini.add((byte) 0x7e);
        ini.add((byte) 0x15);
        ini.add((byte) 0x16);
        
        key.add(ini);
        
        ini = new ArrayList<>();
        ini.add((byte) 0x28);
        ini.add((byte) 0xae);
        ini.add((byte) 0xd2);
        ini.add((byte) 0xa6);
        
        key.add(ini);
        
        ini = new ArrayList<>();
        ini.add((byte) 0xab);
        ini.add((byte) 0xf7);
        ini.add((byte) 0x15);
        ini.add((byte) 0x88);
        
        key.add(ini);
        
        ini = new ArrayList<>();
        ini.add((byte) 0x09);
        ini.add((byte) 0xcf);
        ini.add((byte) 0x4f);
        ini.add((byte) 0x3c);
        
        key.add(ini);
        
        AESOperations op = new AESOperations(key);
        
        System.out.println("Matriz a cifrar:");
        op.printMat(mat);
        System.out.println("Matriz clave (key):");
        op.printMat(key);
        
        op.cipher(mat);
        
        System.out.println("Matriz cifrada:");
        op.printMat(mat);
        
    }
    
}
