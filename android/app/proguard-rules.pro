# Keep JNI entrypoints invoked from libvdpi_android.so
-keep class com.vulninc.vdpi.engine.NativeEngine { *; }
-keep class com.vulninc.vdpi.engine.** { *; }

# Keep kotlinx.serialization generated serializers
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.AnnotationsKt
-keepclassmembers class kotlinx.serialization.json.** {
    *** Companion;
}
-keepclasseswithmembers class kotlinx.serialization.json.** {
    kotlinx.serialization.KSerializer serializer(...);
}
-keep,includedescriptorclasses class com.vulninc.vdpi.**$$serializer { *; }
-keepclassmembers class com.vulninc.vdpi.** {
    *** Companion;
}
-keepclasseswithmembers class com.vulninc.vdpi.** {
    kotlinx.serialization.KSerializer serializer(...);
}
