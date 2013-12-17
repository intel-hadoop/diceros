package com.intel.diceros.test.aes;

import java.io.Serializable;
import java.nio.ByteBuffer;

public class Entity implements Serializable {

  public Entity(byte[] input, byte[] key, byte[] iv ,byte[] decontent,byte[] encontent  ){
    this.input = input;
    this.key = key;
    this.iv = iv;
    this.encontent = encontent;
    this.decontent = decontent;
  }

  public byte[] input;

  public byte[] key;

  public byte[] iv;

  public byte[] encontent;

  public byte[] decontent;

}
