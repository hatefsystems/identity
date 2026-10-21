import { Button, Input, Label, cn } from '@hatef/ui';
import { CircleAlert, Eye, EyeOff, Info, LoaderCircle } from 'lucide-react';
import {
  useEffect,
  useId,
  useRef,
  useState,
  type ComponentProps,
  type FormEventHandler,
  type ReactNode,
} from 'react';
import type { FormStatus } from '../_lib/use-auth-form';

export function AuthField({
  label,
  hint,
  error,
  type = 'text',
  className,
  ...props
}: Omit<ComponentProps<typeof Input>, 'id' | 'aria-describedby' | 'aria-invalid'> & {
  label: string;
  hint?: string;
  error?: string;
}) {
  const id = useId();
  const [visible, setVisible] = useState(false);
  const isPassword = type === 'password';
  const describedBy = [hint && `${id}-hint`, error && `${id}-error`].filter(Boolean).join(' ');

  return (
    <div className="space-y-2">
      <Label htmlFor={id}>{label}</Label>
      <div className="relative">
        <Input
          {...props}
          id={id}
          type={isPassword && visible ? 'text' : type}
          aria-describedby={describedBy || undefined}
          aria-invalid={Boolean(error)}
          className={cn(
            'h-11 min-w-0 border-slate-500 aria-[invalid=true]:border-red-700 dark:border-slate-400 dark:aria-[invalid=true]:border-red-400',
            isPassword && 'pr-12',
            className
          )}
        />
        {isPassword && (
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="absolute right-0 top-0 h-11 w-11 hover:bg-transparent"
            disabled={props.disabled}
            aria-label={`${visible ? 'Hide' : 'Show'} ${label.toLowerCase()}`}
            aria-pressed={visible}
            aria-controls={id}
            onClick={() => setVisible(!visible)}
          >
            {visible ? <EyeOff aria-hidden="true" /> : <Eye aria-hidden="true" />}
          </Button>
        )}
      </div>
      {hint && (
        <p id={`${id}-hint`} className="text-sm leading-relaxed text-muted-foreground">
          {hint}
        </p>
      )}
      {error && (
        <p id={`${id}-error`} className="text-sm text-red-700 dark:text-red-400">
          {error}
        </p>
      )}
    </div>
  );
}

type FormMessages = {
  pending: string;
  success: string;
  error: string;
  cancelled?: string;
  unsupported?: string;
};

function FormFeedback({ status, messages }: { status: FormStatus; messages: FormMessages }) {
  const feedback = useRef<HTMLDivElement>(null);
  const hasError = !['idle', 'pending', 'success'].includes(status);
  const error =
    status === 'rate-limited'
      ? 'Too many attempts. Please try again later.'
      : messages[status as keyof FormMessages] || messages.error;

  useEffect(() => {
    if (status === 'success' || hasError) feedback.current?.focus();
  }, [status, hasError]);

  return (
    <div
      ref={feedback}
      tabIndex={-1}
      className={cn(
        'rounded-md focus:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2',
        status === 'idle' && 'sr-only'
      )}
    >
      <div role="status" aria-live="polite" aria-atomic="true">
        {status === 'pending' && (
          <p className="flex items-start gap-2 text-sm text-muted-foreground">
            <LoaderCircle
              aria-hidden="true"
              className="mt-0.5 size-4 shrink-0 motion-safe:animate-spin"
            />
            {messages.pending}
          </p>
        )}
        {status === 'success' && (
          <p className="rounded-md border border-emerald-700 bg-emerald-50 p-3 text-sm leading-relaxed text-emerald-900 dark:border-emerald-400 dark:bg-emerald-950 dark:text-emerald-200">
            {messages.success}
          </p>
        )}
      </div>
      {hasError && (
        <p
          role="alert"
          className="flex items-start gap-2 rounded-md border border-red-700 bg-red-50 p-3 text-sm leading-relaxed text-red-800 dark:border-red-400 dark:bg-red-950 dark:text-red-200"
        >
          <CircleAlert aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
          {error}
        </p>
      )}
    </div>
  );
}

export function AuthForm({
  label,
  available,
  status,
  onSubmit,
  submitLabel,
  messages,
  children,
}: {
  label: string;
  available: boolean;
  status: FormStatus;
  onSubmit: FormEventHandler<HTMLFormElement>;
  submitLabel: string;
  messages: FormMessages;
  children?: ReactNode;
}) {
  const noticeId = useId();

  return (
    <form method="post" noValidate aria-label={label} onSubmit={onSubmit} className="space-y-5">
      {!available && (
        <div
          id={noticeId}
          className="flex items-start gap-3 rounded-md border bg-muted/50 p-3 text-sm leading-relaxed"
        >
          <Info aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
          <p>
            <span className="block font-medium">UI preview</span>
            This form is not connected yet. Do not enter real credentials.
          </p>
        </div>
      )}
      <FormFeedback status={status} messages={messages} />
      {status !== 'success' && (
        <>
          {children}
          <Button
            type="submit"
            className="h-auto min-h-11 w-full whitespace-normal"
            disabled={!available || status === 'pending'}
            aria-describedby={!available ? noticeId : undefined}
          >
            {status === 'pending' ? messages.pending : submitLabel}
          </Button>
        </>
      )}
    </form>
  );
}
