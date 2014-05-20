package com.intel.diceros.test.util;

import java.io.Serializable;

public class Entity implements Serializable {
  private static final long serialVersionUID = 3137121557455526879L;

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
