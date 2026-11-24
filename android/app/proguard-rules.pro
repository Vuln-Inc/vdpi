# Keep JNI entrypoints and serialization models invoked from libvdpi_android.so
-keep class com.vulninc.vdpi.engine.** { *; }

# Keep kotlinx.serialization generated serializers and Companion metadata
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.AnnotationsKt
-keep,includedescriptorclasses class com.vulninc.vdpi.**$$serializer { *; }
-keepclassmembers class com.vulninc.vdpi.** {
    *** Companion;
}
-keepclasseswithmembers class com.vulninc.vdpi.** {
    kotlinx.serialization.KSerializer serializer(...);
}
