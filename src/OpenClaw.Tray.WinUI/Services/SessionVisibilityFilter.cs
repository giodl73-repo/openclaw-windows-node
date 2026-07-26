using OpenClaw.Chat;
using OpenClaw.Shared;
using OpenClaw.Shared.Sessions;

namespace OpenClawTray.Services;

public static class SessionVisibilityFilter
{
    public static IEnumerable<SessionInfo> VisibleSessions(IEnumerable<SessionInfo> sessions, bool showCompleted)
        => showCompleted ? sessions : sessions.Where(IsVisibleWhenCompletedHidden);

    public static bool IsVisibleWhenCompletedHidden(SessionInfo session)
        => !IsCompleted(session);

    public static bool IsCompleted(SessionInfo session) => SessionRunState.IsCompleted(session);

    public static ChatThreadStatus ToChatThreadStatus(SessionInfo session)
        => SessionRunState.IsWorking(session) ? ChatThreadStatus.Running : ChatThreadStatus.Created;

    public static IEnumerable<ChatThread> VisibleChatPickerThreads(IEnumerable<ChatThread> threads)
        => threads.Where(IsVisibleInChatPicker);

    public static bool IsVisibleInChatPicker(ChatThread thread)
        => thread.Status != ChatThreadStatus.Ended;

    public static string ResolveActiveChannel(string activeChannel, IEnumerable<string> visibleChannels)
    {
        if (!string.Equals(activeChannel, "all", StringComparison.OrdinalIgnoreCase)
            && visibleChannels.Any(channel => string.Equals(channel, activeChannel, StringComparison.OrdinalIgnoreCase)))
        {
            return activeChannel;
        }

        return "all";
    }
}
