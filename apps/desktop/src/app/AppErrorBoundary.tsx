import { Component, type ReactNode } from "react";

export interface AppErrorBoundaryProps {
  children: ReactNode;
  resetKey: string;
}

interface AppErrorBoundaryState {
  failed: boolean;
}

export class AppErrorBoundary extends Component<
  AppErrorBoundaryProps,
  AppErrorBoundaryState
> {
  state: AppErrorBoundaryState = { failed: false };

  static getDerivedStateFromError(): AppErrorBoundaryState {
    return { failed: true };
  }

  componentDidCatch() {
    console.error("application workspace render failed");
  }

  componentDidUpdate(previous: AppErrorBoundaryProps) {
    if (previous.resetKey !== this.props.resetKey && this.state.failed) {
      this.setState({ failed: false });
    }
  }

  render() {
    if (!this.state.failed) {
      return this.props.children;
    }

    return (
      <section className="panel app-error-boundary" role="alert">
        <h2>当前工作区暂时无法显示</h2>
        <p>
          工作区渲染发生错误。错误边界不会发起外部请求，也不会自动读取案件材料。
        </p>
        <button
          type="button"
          onClick={() => this.setState({ failed: false })}
        >
          重试当前工作区
        </button>
      </section>
    );
  }
}
