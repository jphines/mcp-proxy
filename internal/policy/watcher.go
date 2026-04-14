package policy

import (
	"context"
	"log/slog"
	"path/filepath"

	"github.com/fsnotify/fsnotify"
)

// WatchAndReload starts a file system watcher on the policy config path and
// calls engine.Reload() whenever a YAML file changes.
//
// The goroutine exits when ctx is cancelled.
// Reload errors are logged but do not stop the watcher; the existing rule set
// is retained on error (fail-safe: never invalidate a working rule set).
func WatchAndReload(ctx context.Context, e *engine) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}

	// Watch the config path (file or directory).
	if err := watcher.Add(e.configPath); err != nil {
		watcher.Close()
		return err
	}

	go func() {
		defer watcher.Close()
		for {
			select {
			case <-ctx.Done():
				return

			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Op&(fsnotify.Write|fsnotify.Create) == 0 {
					continue
				}
				ext := filepath.Ext(event.Name)
				if ext != ".yaml" && ext != ".yml" {
					continue
				}

				slog.InfoContext(ctx, "policy file changed; reloading",
					slog.String("file", event.Name),
				)
				if err := e.Reload(ctx); err != nil {
					slog.ErrorContext(ctx, "policy reload failed; retaining existing rules",
						slog.String("file", event.Name),
						slog.Any("error", err),
					)
				}

			case watchErr, ok := <-watcher.Errors:
				if !ok {
					return
				}
				slog.WarnContext(ctx, "fsnotify error in policy watcher",
					slog.Any("error", watchErr),
				)
			}
		}
	}()

	return nil
}
