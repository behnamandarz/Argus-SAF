/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.alir.summaryBasedAnalysis.model

import org.argus.amandroid.core.AndroidConstants
import org.argus.jawa.alir.pta._
import org.argus.jawa.alir.pta.reachingFactsAnalysis.RFAFact
import org.argus.jawa.core.JawaType

/**
  * Created by fgwei on 6/15/23.
  */
class BundleSuTest extends SuTestBase("Bundle.safsu") {

  val thisInstance = PTAInstance(new JawaType(AndroidConstants.BUNDLE), defContext)
  val thisFact = new RFAFact(VarSlot("v0"), thisInstance)
  val thisKeyInstance = PTAConcreteStringInstance("key", defContext)
  val thisKeyFact = new RFAFact(FieldSlot(thisInstance, "key"), thisKeyInstance)

  "Landroid/os/Bundle;.<clinit>:()V" with_input () produce ()

  "Landroid/os/Bundle;.<init>:()V" with_input () produce ()

  "Landroid/os/Bundle;.<init>:(I)V" with_input () produce ()

  "Landroid/os/Bundle;.<init>:(Landroid/os/Bundle;)V" with_input (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAInstance(new JawaType(AndroidConstants.BUNDLE), defContext2)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType(AndroidConstants.BUNDLE), defContext2), "key"), PTAPointStringInstance(defContext3)),
    new RFAFact(MapSlot(PTAInstance(new JawaType(AndroidConstants.BUNDLE), defContext2), PTAPointStringInstance(defContext3)), PTAPointStringInstance(defContext4))
  ) produce (
    thisFact,
    new RFAFact(FieldSlot(thisInstance, "key"), PTAPointStringInstance(defContext3)),
    new RFAFact(VarSlot("v1"), PTAInstance(new JawaType(AndroidConstants.BUNDLE), defContext2)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType(AndroidConstants.BUNDLE), defContext2), "key"), PTAPointStringInstance(defContext3)),
    new RFAFact(MapSlot(PTAInstance(new JawaType(AndroidConstants.BUNDLE), defContext2), PTAPointStringInstance(defContext3)), PTAPointStringInstance(defContext4))
  )

  "Landroid/os/Bundle;.<init>:(Ljava/lang/ClassLoader;)V" with_input () produce ()

  "Landroid/os/Bundle;.clear:()V" with_input (
    thisFact,
    new RFAFact(FieldSlot(thisInstance, "key"), PTAPointStringInstance(defContext2)),
    new RFAFact(MapSlot(thisInstance, PTAPointStringInstance(defContext2)), PTAPointStringInstance(defContext3))
  ) produce thisFact

  "Landroid/os/Bundle;.clone:()Ljava/lang/Object;" with_input (
    thisFact,
    new RFAFact(FieldSlot(thisInstance, "key"), PTAPointStringInstance(defContext2)),
    new RFAFact(MapSlot(thisInstance, PTAPointStringInstance(defContext2)), PTAPointStringInstance(defContext3))
  ) produce (
    thisFact,
    new RFAFact(FieldSlot(thisInstance, "key"), PTAPointStringInstance(defContext2)),
    new RFAFact(MapSlot(thisInstance, PTAPointStringInstance(defContext2)), PTAPointStringInstance(defContext3)),
    new RFAFact(VarSlot("temp"), PTAInstance(new JawaType(AndroidConstants.BUNDLE), defContext))
  )

  "Landroid/os/Bundle;.containsKey:(Ljava/lang/String;)Z" with_input () produce ()

  "Landroid/os/Bundle;.describeContents:()I" with_input () produce ()

  "Landroid/os/Bundle;.forPair:(Ljava/lang/String;Ljava/lang/String;)Landroid/os/Bundle;" with_input (
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("v2"), PTAConcreteStringInstance("value", defContext3))
  ) produce (
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("v2"), PTAConcreteStringInstance("value", defContext3)),
    new RFAFact(VarSlot("temp"), PTAInstance(new JawaType(AndroidConstants.BUNDLE), currentContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType(AndroidConstants.BUNDLE), currentContext), "key"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(MapSlot(PTAInstance(new JawaType(AndroidConstants.BUNDLE), currentContext), PTAConcreteStringInstance("key", defContext2)), PTAConcreteStringInstance("value", defContext3))
  )

  "Landroid/os/Bundle;.get:(Ljava/lang/String;)Ljava/lang/Object;" with_input (
    thisFact,
    new RFAFact(FieldSlot(thisInstance, "key"), PTAPointStringInstance(defContext2)),
    new RFAFact(MapSlot(thisInstance, PTAPointStringInstance(defContext2)), PTAPointStringInstance(defContext3)),
    new RFAFact(VarSlot("v1"), PTAPointStringInstance(defContext2))
  ) produce (
    thisFact,
    new RFAFact(FieldSlot(thisInstance, "key"), PTAPointStringInstance(defContext2)),
    new RFAFact(MapSlot(thisInstance, PTAPointStringInstance(defContext2)), PTAPointStringInstance(defContext3)),
    new RFAFact(VarSlot("v1"), PTAPointStringInstance(defContext2)),
    new RFAFact(VarSlot("temp"), PTAPointStringInstance(defContext3))
  )

  "Landroid/os/Bundle;.getBoolean:(Ljava/lang/String;)Z" with_input () produce ()

  "Landroid/os/Bundle;.getBoolean:(Ljava/lang/String;Z)Z" with_input () produce ()

  "Landroid/os/Bundle;.getBooleanArray:(Ljava/lang/String;)[Z" with_input (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAInstance(new JawaType("boolean", 1), defContext)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2))
  ) produce (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAInstance(new JawaType("boolean", 1), defContext)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("temp"), PTAInstance(new JawaType("boolean", 1), defContext))
  )

  "Landroid/os/Bundle;.getBundle:(Ljava/lang/String;)Landroid/os/Bundle;" with_input (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAInstance(new JawaType(AndroidConstants.BUNDLE), defContext)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2))
  ) produce (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAInstance(new JawaType(AndroidConstants.BUNDLE), defContext)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("temp"), PTAInstance(new JawaType(AndroidConstants.BUNDLE), defContext))
  )

  "Landroid/os/Bundle;.getByte:(Ljava/lang/String;)B" with_input () produce ()

  "Landroid/os/Bundle;.getByte:(Ljava/lang/String;B)Ljava/lang/Byte;" with_input () produce ()

  "Landroid/os/Bundle;.getByteArray:(Ljava/lang/String;)[B" with_input (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAInstance(new JawaType("byte", 1), defContext)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2))
  ) produce (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAInstance(new JawaType("byte", 1), defContext)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("temp"), PTAInstance(new JawaType("byte", 1), defContext))
  )

  "Landroid/os/Bundle;.getChar:(Ljava/lang/String;)C" with_input () produce ()

  "Landroid/os/Bundle;.getChar:(Ljava/lang/String;C)C" with_input () produce ()

  "Landroid/os/Bundle;.getCharArray:(Ljava/lang/String;)[C" with_input (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAInstance(new JawaType("char", 1), defContext)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2))
  ) produce (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAInstance(new JawaType("char", 1), defContext)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("temp"), PTAInstance(new JawaType("char", 1), defContext))
  )

  "Landroid/os/Bundle;.getCharSequence:(Ljava/lang/String;)Ljava/lang/CharSequence;" with_input (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAConcreteStringInstance("value", defContext)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2))
  ) produce (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAConcreteStringInstance("value", defContext)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("temp"), PTAConcreteStringInstance("value", defContext))
  )

  "Landroid/os/Bundle;.getCharSequence:(Ljava/lang/String;Ljava/lang/CharSequence;)Ljava/lang/CharSequence;" with_input (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAConcreteStringInstance("value", defContext)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("v2"), PTAConcreteStringInstance("value", defContext3))
  ) produce (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAConcreteStringInstance("value", defContext)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("v2"), PTAConcreteStringInstance("value", defContext3)),
    new RFAFact(VarSlot("temp"), PTAConcreteStringInstance("value", defContext)),
    new RFAFact(VarSlot("temp"), PTAConcreteStringInstance("value", defContext3))
  )

  "Landroid/os/Bundle;.getCharSequenceArray:(Ljava/lang/String;)[Ljava/lang/CharSequence;" with_input (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAInstance(new JawaType("java.lang.String", 1), defContext)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2))
  ) produce (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAInstance(new JawaType("java.lang.String", 1), defContext)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.lang.String", 1), defContext))
  )

  "Landroid/os/Bundle;.getCharSequenceArrayList:(Ljava/lang/String;)Ljava/util/ArrayList;" with_input (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAInstance(new JawaType("java.util.ArrayList"), defContext)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2))
  ) produce (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAInstance(new JawaType("java.util.ArrayList"), defContext)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.util.ArrayList"), defContext))
  )

  "Landroid/os/Bundle;.getClassLoader:()Ljava/lang/ClassLoader;" with_input (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAInstance(new JawaType("boolean", 1), defContext)),
  ) produce (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAInstance(new JawaType("boolean", 1), defContext)),
    new RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.lang.ClassLoader").toUnknown, currentContext))
  )

  "Landroid/os/Bundle;.getDouble:(Ljava/lang/String;)D" with_input () produce ()

  "Landroid/os/Bundle;.getDouble:(Ljava/lang/String;D)D" with_input () produce ()

  "Landroid/os/Bundle;.getDoubleArray:(Ljava/lang/String;)[D" with_input (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAInstance(new JawaType("double", 1), defContext)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2))
  ) produce (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAInstance(new JawaType("double", 1), defContext)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("temp"), PTAInstance(new JawaType("double", 1), defContext))
  )

  "Landroid/os/Bundle;.getFloat:(Ljava/lang/String;)F" with_input () produce ()

  "Landroid/os/Bundle;.getFloat:(Ljava/lang/String;F)F" with_input () produce ()

  "Landroid/os/Bundle;.getFloatArray:(Ljava/lang/String;)[F" with_input (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAInstance(new JawaType("float", 1), defContext)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2))
  ) produce (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAInstance(new JawaType("float", 1), defContext)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("temp"), PTAInstance(new JawaType("float", 1), defContext))
  )

  "Landroid/os/Bundle;.getIBinder:(Ljava/lang/String;)Landroid/os/IBinder;" with_input (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAInstance(new JawaType("android.os.Binder"), defContext)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2))
  ) produce (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAInstance(new JawaType("android.os.Binder"), defContext)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("temp"), PTAInstance(new JawaType("android.os.Binder"), defContext))
  )

  "Landroid/os/Bundle;.getInt:(Ljava/lang/String;)I" with_input () produce ()

  "Landroid/os/Bundle;.getInt:(Ljava/lang/String;I)I" with_input () produce ()

  "Landroid/os/Bundle;.getIntArray:(Ljava/lang/String;)[I" with_input (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAInstance(new JawaType("int", 1), defContext)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2))
  ) produce (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAInstance(new JawaType("int", 1), defContext)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("temp"), PTAInstance(new JawaType("int", 1), defContext))
  )

  "Landroid/os/Bundle;.getIntegerArrayList:(Ljava/lang/String;)Ljava/util/ArrayList;" with_input (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAInstance(new JawaType("java.util.ArrayList"), defContext)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2))
  ) produce (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAInstance(new JawaType("java.util.ArrayList"), defContext)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.util.ArrayList"), defContext))
  )

  "Landroid/os/Bundle;.getLong:(Ljava/lang/String;)J" with_input () produce ()

  "Landroid/os/Bundle;.getLong:(Ljava/lang/String;J)J" with_input () produce ()

  "Landroid/os/Bundle;.getLongArray:(Ljava/lang/String;)[J" with_input (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAInstance(new JawaType("long", 1), defContext)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2))
  ) produce (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAInstance(new JawaType("long", 1), defContext)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("temp"), PTAInstance(new JawaType("long", 1), defContext))
  )

  "Landroid/os/Bundle;.getParcelable:(Ljava/lang/String;)Landroid/os/Parcelable;" with_input (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAInstance(new JawaType("android.os.Parcelable").toUnknown, defContext)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2))
  ) produce (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAInstance(new JawaType("android.os.Parcelable").toUnknown, defContext)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("temp"), PTAInstance(new JawaType("android.os.Parcelable").toUnknown, defContext))
  )

  "Landroid/os/Bundle;.getParcelableArray:(Ljava/lang/String;)[Landroid/os/Parcelable;" with_input (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAInstance(new JawaType("android.os.Parcelable", 1), defContext)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2))
  ) produce (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAInstance(new JawaType("android.os.Parcelable", 1), defContext)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("temp"), PTAInstance(new JawaType("android.os.Parcelable", 1), defContext))
  )

  "Landroid/os/Bundle;.getParcelableArrayList:(Ljava/lang/String;)Ljava/util/ArrayList;" with_input (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAInstance(new JawaType("java.util.ArrayList"), defContext)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2))
  ) produce (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAInstance(new JawaType("java.util.ArrayList"), defContext)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.util.ArrayList"), defContext))
  )

  "Landroid/os/Bundle;.getSerializable:(Ljava/lang/String;)Ljava/io/Serializable;" with_input (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAInstance(new JawaType("java.io.Serializable").toUnknown, defContext)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2))
  ) produce (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAInstance(new JawaType("java.io.Serializable").toUnknown, defContext)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.io.Serializable").toUnknown, defContext))
  )

  "Landroid/os/Bundle;.getShort:(Ljava/lang/String;)S" with_input () produce ()

  "Landroid/os/Bundle;.getShort:(Ljava/lang/String;S)S" with_input () produce ()

  "Landroid/os/Bundle;.getShortArray:(Ljava/lang/String;)[S" with_input (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAInstance(new JawaType("short", 1), defContext)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2))
  ) produce (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAInstance(new JawaType("short", 1), defContext)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("temp"), PTAInstance(new JawaType("short", 1), defContext))
  )

  "Landroid/os/Bundle;.getSparseParcelableArray:(Ljava/lang/String;)Landroid/util/SparseArray;" with_input (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAInstance(new JawaType("android.util.SparseArray"), defContext)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2))
  ) produce (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAInstance(new JawaType("android.util.SparseArray"), defContext)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("temp"), PTAInstance(new JawaType("android.util.SparseArray"), defContext))
  )

  "Landroid/os/Bundle;.getString:(Ljava/lang/String;)Ljava/lang/String;" with_input (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAConcreteStringInstance("value", defContext)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2))
  ) produce (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAConcreteStringInstance("value", defContext)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("temp"), PTAConcreteStringInstance("value", defContext))
  )

  "Landroid/os/Bundle;.getString:(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;" with_input (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAConcreteStringInstance("value", defContext)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("v2"), PTAConcreteStringInstance("value", defContext3))
  ) produce (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAConcreteStringInstance("value", defContext)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("v2"), PTAConcreteStringInstance("value", defContext3)),
    new RFAFact(VarSlot("temp"), PTAConcreteStringInstance("value", defContext)),
    new RFAFact(VarSlot("temp"), PTAConcreteStringInstance("value", defContext3))
  )

  "Landroid/os/Bundle;.getStringArray:(Ljava/lang/String;)[Ljava/lang/String;" with_input (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAInstance(new JawaType("java.lang.String", 1), defContext)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2))
  ) produce (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAInstance(new JawaType("java.lang.String", 1), defContext)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.lang.String", 1), defContext))
  )

  "Landroid/os/Bundle;.getStringArrayList:(Ljava/lang/String;)Ljava/util/ArrayList;" with_input (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAInstance(new JawaType("java.util.ArrayList"), defContext)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2))
  ) produce (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAInstance(new JawaType("java.util.ArrayList"), defContext)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.util.ArrayList"), defContext))
  )

  "Landroid/os/Bundle;.hasFileDescriptors:()Z" with_input () produce ()

  "Landroid/os/Bundle;.isEmpty:()Z" with_input () produce ()

  "Landroid/os/Bundle;.isParcelled:()Z" with_input () produce ()

  "Landroid/os/Bundle;.keySet:()Ljava/util/Set;" with_input (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAInstance(new JawaType("java.util.ArrayList"), defContext))
  ) produce (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAInstance(new JawaType("java.util.ArrayList"), defContext)),
    new RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.util.HashSet"), currentContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashSet"), currentContext), "items"), thisKeyInstance)
  )

  "Landroid/os/Bundle;.putAll:(Landroid/os/Bundle;)V" with_input (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAInstance(new JawaType("java.util.ArrayList"), defContext)),
    new RFAFact(VarSlot("v1"), PTAInstance(new JawaType(AndroidConstants.BUNDLE), defContext2)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType(AndroidConstants.BUNDLE), defContext2), "key"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(MapSlot(PTAInstance(new JawaType(AndroidConstants.BUNDLE), defContext2), PTAConcreteStringInstance("key", defContext2)), PTAInstance(new JawaType("java.util.ArrayList"), defContext2))
  ) produce (
    thisFact,
    thisKeyFact,
    new RFAFact(FieldSlot(thisInstance, "key"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAInstance(new JawaType("java.util.ArrayList"), defContext)),
    new RFAFact(VarSlot("v1"), PTAInstance(new JawaType(AndroidConstants.BUNDLE), defContext2)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType(AndroidConstants.BUNDLE), defContext2), "key"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(MapSlot(PTAInstance(new JawaType(AndroidConstants.BUNDLE), defContext2), PTAConcreteStringInstance("key", defContext2)), PTAInstance(new JawaType("java.util.ArrayList"), defContext2))
  )

  "Landroid/os/Bundle;.putBoolean:(Ljava/lang/String;Z)V" with_input () produce ()

  "Landroid/os/Bundle;.putBooleanArray:(Ljava/lang/String;[Z)V" with_input (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("v2"), PTAInstance(new JawaType("boolean", 1), defContext3))
  ) produce (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("v2"), PTAInstance(new JawaType("boolean", 1), defContext3)),
    new RFAFact(FieldSlot(thisInstance, "key"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(MapSlot(thisInstance, PTAConcreteStringInstance("key", defContext2)), PTAInstance(new JawaType("boolean", 1), defContext3))
  )

  "Landroid/os/Bundle;.putBundle:(Ljava/lang/String;Landroid/os/Bundle;)V" with_input (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("v2"), PTAInstance(new JawaType(AndroidConstants.BUNDLE), defContext3))
  ) produce (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("v2"), PTAInstance(new JawaType(AndroidConstants.BUNDLE), defContext3)),
    new RFAFact(FieldSlot(thisInstance, "key"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(MapSlot(thisInstance, PTAConcreteStringInstance("key", defContext2)), PTAInstance(new JawaType(AndroidConstants.BUNDLE), defContext3))
  )

  "Landroid/os/Bundle;.putByte:(Ljava/lang/String;B)V" with_input () produce ()

  "Landroid/os/Bundle;.putByteArray:(Ljava/lang/String;[B)V" with_input (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("v2"), PTAInstance(new JawaType("byte", 1), defContext3))
  ) produce (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("v2"), PTAInstance(new JawaType("byte", 1), defContext3)),
    new RFAFact(FieldSlot(thisInstance, "key"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(MapSlot(thisInstance, PTAConcreteStringInstance("key", defContext2)), PTAInstance(new JawaType("byte", 1), defContext3))
  )

  "Landroid/os/Bundle;.putChar:(Ljava/lang/String;C)V" with_input () produce ()

  "Landroid/os/Bundle;.putCharArray:(Ljava/lang/String;[C)V" with_input (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("v2"), PTAInstance(new JawaType("char", 1), defContext3))
  ) produce (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("v2"), PTAInstance(new JawaType("char", 1), defContext3)),
    new RFAFact(FieldSlot(thisInstance, "key"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(MapSlot(thisInstance, PTAConcreteStringInstance("key", defContext2)), PTAInstance(new JawaType("char", 1), defContext3))
  )

  "Landroid/os/Bundle;.putCharSequence:(Ljava/lang/String;Ljava/lang/CharSequence;)V" with_input (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("v2"), PTAConcreteStringInstance("value", defContext3))
  ) produce (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("v2"), PTAConcreteStringInstance("value", defContext3)),
    new RFAFact(FieldSlot(thisInstance, "key"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(MapSlot(thisInstance, PTAConcreteStringInstance("key", defContext2)), PTAConcreteStringInstance("value", defContext3))
  )

  "Landroid/os/Bundle;.putCharSequenceArray:(Ljava/lang/String;[Ljava/lang/CharSequence;)V" with_input (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("v2"), PTAInstance(new JawaType("java.lang.String", 1), defContext3))
  ) produce (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("v2"), PTAInstance(new JawaType("java.lang.String", 1), defContext3)),
    new RFAFact(FieldSlot(thisInstance, "key"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(MapSlot(thisInstance, PTAConcreteStringInstance("key", defContext2)), PTAInstance(new JawaType("java.lang.String", 1), defContext3))
  )

  "Landroid/os/Bundle;.putCharSequenceArrayList:(Ljava/lang/String;Ljava/util/ArrayList;)V" with_input (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("v2"), PTAInstance(new JawaType("java.util.ArrayList"), defContext3))
  ) produce (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("v2"), PTAInstance(new JawaType("java.util.ArrayList"), defContext3)),
    new RFAFact(FieldSlot(thisInstance, "key"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(MapSlot(thisInstance, PTAConcreteStringInstance("key", defContext2)), PTAInstance(new JawaType("java.util.ArrayList"), defContext3))
  )

  "Landroid/os/Bundle;.putDouble:(Ljava/lang/String;D)V" with_input () produce ()

  "Landroid/os/Bundle;.putDoubleArray:(Ljava/lang/String;[D)V" with_input (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("v2"), PTAInstance(new JawaType("double", 1), defContext3))
  ) produce (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("v2"), PTAInstance(new JawaType("double", 1), defContext3)),
    new RFAFact(FieldSlot(thisInstance, "key"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(MapSlot(thisInstance, PTAConcreteStringInstance("key", defContext2)), PTAInstance(new JawaType("double", 1), defContext3))
  )

  "Landroid/os/Bundle;.putFloat:(Ljava/lang/String;F)V" with_input () produce ()

  "Landroid/os/Bundle;.putFloatArray:(Ljava/lang/String;[F)V" with_input (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("v2"), PTAInstance(new JawaType("float", 1), defContext3))
  ) produce (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("v2"), PTAInstance(new JawaType("float", 1), defContext3)),
    new RFAFact(FieldSlot(thisInstance, "key"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(MapSlot(thisInstance, PTAConcreteStringInstance("key", defContext2)), PTAInstance(new JawaType("float", 1), defContext3))
  )

  "Landroid/os/Bundle;.putIBinder:(Ljava/lang/String;Landroid/os/IBinder;)V" with_input (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("v2"), PTAInstance(new JawaType("android.os.Binder"), defContext3))
  ) produce (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("v2"), PTAInstance(new JawaType("android.os.Binder"), defContext3)),
    new RFAFact(FieldSlot(thisInstance, "key"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(MapSlot(thisInstance, PTAConcreteStringInstance("key", defContext2)), PTAInstance(new JawaType("android.os.Binder"), defContext3))
  )

  "Landroid/os/Bundle;.putInt:(Ljava/lang/String;I)V" with_input () produce ()

  "Landroid/os/Bundle;.putIntArray:(Ljava/lang/String;[I)V" with_input (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("v2"), PTAInstance(new JawaType("int", 1), defContext3))
  ) produce (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("v2"), PTAInstance(new JawaType("int", 1), defContext3)),
    new RFAFact(FieldSlot(thisInstance, "key"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(MapSlot(thisInstance, PTAConcreteStringInstance("key", defContext2)), PTAInstance(new JawaType("int", 1), defContext3))
  )

  "Landroid/os/Bundle;.putIntegerArrayList:(Ljava/lang/String;Ljava/util/ArrayList;)V" with_input (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("v2"), PTAInstance(new JawaType("java.util.ArrayList"), defContext3))
  ) produce (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("v2"), PTAInstance(new JawaType("java.util.ArrayList"), defContext3)),
    new RFAFact(FieldSlot(thisInstance, "key"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(MapSlot(thisInstance, PTAConcreteStringInstance("key", defContext2)), PTAInstance(new JawaType("java.util.ArrayList"), defContext3))
  )

  "Landroid/os/Bundle;.putLong:(Ljava/lang/String;J)V" with_input () produce ()

  "Landroid/os/Bundle;.putLongArray:(Ljava/lang/String;[J)V" with_input (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("v2"), PTAInstance(new JawaType("long", 1), defContext3))
  ) produce (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("v2"), PTAInstance(new JawaType("long", 1), defContext3)),
    new RFAFact(FieldSlot(thisInstance, "key"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(MapSlot(thisInstance, PTAConcreteStringInstance("key", defContext2)), PTAInstance(new JawaType("long", 1), defContext3))
  )

  "Landroid/os/Bundle;.putParcelable:(Ljava/lang/String;Landroid/os/Parcelable;)V" with_input (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("v2"), PTAInstance(new JawaType("android.os.Parcelable").toUnknown, defContext3))
  ) produce (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("v2"), PTAInstance(new JawaType("android.os.Parcelable").toUnknown, defContext3)),
    new RFAFact(FieldSlot(thisInstance, "key"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(MapSlot(thisInstance, PTAConcreteStringInstance("key", defContext2)), PTAInstance(new JawaType("android.os.Parcelable").toUnknown, defContext3))
  )

  "Landroid/os/Bundle;.putParcelableArray:(Ljava/lang/String;[Landroid/os/Parcelable;)V" with_input (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("v2"), PTAInstance(new JawaType("android.os.Parcelable", 1), defContext3))
  ) produce (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("v2"), PTAInstance(new JawaType("android.os.Parcelable", 1), defContext3)),
    new RFAFact(FieldSlot(thisInstance, "key"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(MapSlot(thisInstance, PTAConcreteStringInstance("key", defContext2)), PTAInstance(new JawaType("android.os.Parcelable", 1), defContext3))
  )

  "Landroid/os/Bundle;.putParcelableArrayList:(Ljava/lang/String;Ljava/util/ArrayList;)V" with_input (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("v2"), PTAInstance(new JawaType("java.util.ArrayList"), defContext3))
  ) produce (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("v2"), PTAInstance(new JawaType("java.util.ArrayList"), defContext3)),
    new RFAFact(FieldSlot(thisInstance, "key"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(MapSlot(thisInstance, PTAConcreteStringInstance("key", defContext2)), PTAInstance(new JawaType("java.util.ArrayList"), defContext3))
  )

  "Landroid/os/Bundle;.putSerializable:(Ljava/lang/String;Ljava/io/Serializable;)V" with_input (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("v2"), PTAInstance(new JawaType("java.io.Serializable").toUnknown, defContext3))
  ) produce (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("v2"), PTAInstance(new JawaType("java.io.Serializable").toUnknown, defContext3)),
    new RFAFact(FieldSlot(thisInstance, "key"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(MapSlot(thisInstance, PTAConcreteStringInstance("key", defContext2)), PTAInstance(new JawaType("java.io.Serializable").toUnknown, defContext3))
  )

  "Landroid/os/Bundle;.putShort:(Ljava/lang/String;S)V" with_input () produce ()

  "Landroid/os/Bundle;.putShortArray:(Ljava/lang/String;[S)V" with_input (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("v2"), PTAInstance(new JawaType("short", 1), defContext3))
  ) produce (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("v2"), PTAInstance(new JawaType("short", 1), defContext3)),
    new RFAFact(FieldSlot(thisInstance, "key"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(MapSlot(thisInstance, PTAConcreteStringInstance("key", defContext2)), PTAInstance(new JawaType("short", 1), defContext3))
  )

  "Landroid/os/Bundle;.putSparseParcelableArray:(Ljava/lang/String;Landroid/util/SparseArray;)V" with_input (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("v2"), PTAInstance(new JawaType("android.util.SparseArray"), defContext3))
  ) produce (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("v2"), PTAInstance(new JawaType("android.util.SparseArray"), defContext3)),
    new RFAFact(FieldSlot(thisInstance, "key"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(MapSlot(thisInstance, PTAConcreteStringInstance("key", defContext2)), PTAInstance(new JawaType("android.util.SparseArray"), defContext3))
  )

  "Landroid/os/Bundle;.putString:(Ljava/lang/String;Ljava/lang/String;)V" with_input (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("v2"), PTAConcreteStringInstance("value", defContext3))
  ) produce (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("v2"), PTAConcreteStringInstance("value", defContext3)),
    new RFAFact(FieldSlot(thisInstance, "key"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(MapSlot(thisInstance, PTAConcreteStringInstance("key", defContext2)), PTAConcreteStringInstance("value", defContext3))
  )

  "Landroid/os/Bundle;.putStringArray:(Ljava/lang/String;[Ljava/lang/String;)V" with_input (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("v2"), PTAInstance(new JawaType("java.lang.String", 1), defContext3))
  ) produce (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("v2"), PTAInstance(new JawaType("java.lang.String", 1), defContext3)),
    new RFAFact(FieldSlot(thisInstance, "key"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(MapSlot(thisInstance, PTAConcreteStringInstance("key", defContext2)), PTAInstance(new JawaType("java.lang.String", 1), defContext3))
  )

  "Landroid/os/Bundle;.putStringArrayList:(Ljava/lang/String;Ljava/util/ArrayList;)V" with_input (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("v2"), PTAInstance(new JawaType("java.util.ArrayList"), defContext3))
  ) produce (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(VarSlot("v2"), PTAInstance(new JawaType("java.util.ArrayList"), defContext3)),
    new RFAFact(FieldSlot(thisInstance, "key"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(MapSlot(thisInstance, PTAConcreteStringInstance("key", defContext2)), PTAInstance(new JawaType("java.util.ArrayList"), defContext3))
  )

  "Landroid/os/Bundle;.readFromParcel:(Landroid/os/Parcel;)V" with_input () produce ()


  "Landroid/os/Bundle;.remove:(Ljava/lang/String;)V" with_input (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAInstance(new JawaType("java.util.ArrayList"), defContext)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext))
  ) produce (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("key", defContext))
  )

  "Landroid/os/Bundle;.setAllowFds:(Z)Z" with_input () produce ()

  "Landroid/os/Bundle;.setClassLoader:(Ljava/lang/ClassLoader;)V" with_input () produce ()

  "Landroid/os/Bundle;.size:()I" with_input () produce ()

  "Landroid/os/Bundle;.toString:()Ljava/lang/String;" with_input (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAInstance(new JawaType("java.util.ArrayList"), defContext))
  ) produce (
    thisFact,
    thisKeyFact,
    new RFAFact(MapSlot(thisInstance, thisKeyInstance), PTAInstance(new JawaType("java.util.ArrayList"), defContext)),
    new RFAFact(VarSlot("temp"), PTAPointStringInstance(currentContext))
  )

  "Landroid/os/Bundle;.unparcel:()V" with_input () produce ()

  "Landroid/os/Bundle;.writeToParcel:(Landroid/os/Parcel;I)V" with_input () produce ()
}
