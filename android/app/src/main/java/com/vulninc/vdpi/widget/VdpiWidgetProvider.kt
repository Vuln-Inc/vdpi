package com.vulninc.vdpi.widget

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.widget.RemoteViews
import com.vulninc.vdpi.MainActivity
import com.vulninc.vdpi.R
import com.vulninc.vdpi.data.SettingsRepository
import com.vulninc.vdpi.vpn.TunnelPhase
import com.vulninc.vdpi.vpn.TunnelRuntimeState
import com.vulninc.vdpi.vpn.VdpiVpnService

class VdpiWidgetProvider : AppWidgetProvider() {

    override fun onUpdate(
        context: Context,
        appWidgetManager: AppWidgetManager,
        appWidgetIds: IntArray,
    ) {
        if (appWidgetIds.isEmpty()) return
        val views = buildRemoteViews(context)
        appWidgetManager.updateAppWidget(appWidgetIds, views)
    }

    companion object {
        const val ACTION_TOGGLE_WIDGET = "com.vulninc.vdpi.action.TOGGLE_WIDGET"

        private const val REQ_OPEN_APP = 100
        private const val REQ_TOGGLE_WIDGET = 101
        private const val REQ_CONNECT_ACTIVITY = 102

        private const val COLOR_DOT_CONNECTED = 0xFF30D158.toInt()
        private const val COLOR_DOT_CONNECTING = 0xFFFF9F0A.toInt()
        private const val COLOR_DOT_OFF = 0xFF8E8E93.toInt()
        private const val COLOR_DOT_ERROR = 0xFFFF453A.toInt()

        fun requestUpdate(context: Context) {
            val appContext = context.applicationContext ?: context
            runCatching {
                val manager = AppWidgetManager.getInstance(appContext) ?: return
                val component = ComponentName(appContext, VdpiWidgetProvider::class.java)
                val widgetIds = manager.getAppWidgetIds(component)
                if (widgetIds.isEmpty()) return
                manager.updateAppWidget(widgetIds, buildRemoteViews(appContext))
            }
        }

        internal fun handleToggle(context: Context) {
            val phase = TunnelRuntimeState.state.value.phase
            if (phase == TunnelPhase.CONNECTED || phase == TunnelPhase.CONNECTING) {
                VdpiVpnService.stop(context)
                requestUpdate(context)
                return
            }

            val consentNeeded = runCatching { VpnService.prepare(context) != null }.getOrDefault(true)
            if (consentNeeded) {
                val strings = SettingsRepository.resolveStrings(context)
                TunnelRuntimeState.update {
                    it.copy(
                        phase = TunnelPhase.ERROR,
                        errorMessage = strings.feedbackVpnPermissionRequired,
                    )
                }
                requestUpdate(context)
                return
            }

            if (!VdpiVpnService.start(context)) {
                requestUpdate(context)
            }
        }

        private fun buildRemoteViews(context: Context): RemoteViews {
            val phase = TunnelRuntimeState.state.value.phase
            val strings = SettingsRepository.resolveStrings(context)
            val dotColor: Int
            val subtitleText: String
            val actionText: String
            when (phase) {
                TunnelPhase.CONNECTED -> {
                    dotColor = COLOR_DOT_CONNECTED
                    subtitleText = strings.widgetStatusConnected
                    actionText = strings.widgetActionDisconnect
                }
                TunnelPhase.CONNECTING -> {
                    dotColor = COLOR_DOT_CONNECTING
                    subtitleText = strings.widgetStatusConnecting
                    actionText = strings.widgetActionDisconnect
                }
                TunnelPhase.DISCONNECTED -> {
                    dotColor = COLOR_DOT_OFF
                    subtitleText = strings.widgetStatusOff
                    actionText = strings.widgetActionConnect
                }
                TunnelPhase.ERROR -> {
                    dotColor = COLOR_DOT_ERROR
                    subtitleText = strings.widgetStatusError
                    actionText = strings.widgetActionConnect
                }
            }

            val openAppIntent = Intent(context, MainActivity::class.java).apply {
                addFlags(
                    Intent.FLAG_ACTIVITY_NEW_TASK or
                        Intent.FLAG_ACTIVITY_CLEAR_TOP or
                        Intent.FLAG_ACTIVITY_SINGLE_TOP,
                )
            }
            val openAppPendingIntent = PendingIntent.getActivity(
                context,
                REQ_OPEN_APP,
                openAppIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            )

            val launchActivityToConnect =
                (phase == TunnelPhase.DISCONNECTED || phase == TunnelPhase.ERROR) &&
                    (phase == TunnelPhase.ERROR || runCatching { VpnService.prepare(context) != null }.getOrDefault(true))

            val togglePendingIntent = if (launchActivityToConnect) {
                val connectIntent = Intent(context, MainActivity::class.java).apply {
                    addFlags(
                        Intent.FLAG_ACTIVITY_NEW_TASK or
                            Intent.FLAG_ACTIVITY_CLEAR_TOP or
                            Intent.FLAG_ACTIVITY_SINGLE_TOP,
                    )
                    putExtra(MainActivity.EXTRA_AUTO_CONNECT, true)
                }
                PendingIntent.getActivity(
                    context,
                    REQ_CONNECT_ACTIVITY,
                    connectIntent,
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
                )
            } else {
                val toggleIntent = Intent(context, VdpiWidgetActionReceiver::class.java).apply {
                    action = ACTION_TOGGLE_WIDGET
                }
                PendingIntent.getBroadcast(
                    context,
                    REQ_TOGGLE_WIDGET,
                    toggleIntent,
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
                )
            }

            return RemoteViews(context.packageName, R.layout.widget_vdpi).apply {
                setInt(R.id.widget_status_dot, "setColorFilter", dotColor)
                setTextViewText(R.id.widget_title, context.getString(R.string.app_name))
                setTextViewText(R.id.widget_subtitle, subtitleText)
                setTextViewText(R.id.widget_toggle_button, actionText)
                setOnClickPendingIntent(R.id.widget_info_container, openAppPendingIntent)
                setOnClickPendingIntent(R.id.widget_toggle_button, togglePendingIntent)
            }
        }
    }
}

class VdpiWidgetActionReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == VdpiWidgetProvider.ACTION_TOGGLE_WIDGET) {
            VdpiWidgetProvider.handleToggle(context.applicationContext ?: context)
        }
    }
}
