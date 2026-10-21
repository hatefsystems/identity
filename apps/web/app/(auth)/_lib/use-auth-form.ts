import { useEffect, useRef, useState, type ChangeEvent, type FormEvent } from 'react';
import type { FieldErrors } from './validation';

// Presentation outcomes, not an API contract. Public screens supply no submit handler.
export type FormOutcome = 'success' | 'error' | 'cancelled' | 'unsupported' | 'rate-limited';
export type FormStatus = 'idle' | 'pending' | FormOutcome;
export type FormSubmit<T> = (values: T) => Promise<FormOutcome>;

export function useAuthForm<T extends Record<string, string>>(
  initialValues: T,
  validate: (values: T) => FieldErrors<T>,
  submit?: FormSubmit<T>
) {
  const [values, setValues] = useState(initialValues);
  const [errors, setErrors] = useState<FieldErrors<T>>({});
  const [status, setStatus] = useState<FormStatus>('idle');
  const touched = useRef(new Set<keyof T>());
  const inFlight = useRef(false);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  function validateTouched(nextValues: T) {
    const nextErrors = validate(nextValues);
    setErrors(
      Object.fromEntries(
        [...touched.current].map((name) => [name, nextErrors[name]])
      ) as FieldErrors<T>
    );
  }

  function field(name: keyof T & string) {
    return {
      name,
      value: values[name],
      error: errors[name],
      disabled: status === 'pending',
      onBlur: () => {
        touched.current.add(name);
        validateTouched(values);
      },
      onChange: (event: ChangeEvent<HTMLInputElement>) => {
        const nextValues = { ...values, [name]: event.target.value };
        setValues(nextValues);
        validateTouched(nextValues);
        if (status !== 'pending') setStatus('idle');
      },
    };
  }

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!submit || inFlight.current || status === 'success') return;

    // Read the actual controls so password-manager autofill need not emit React change events.
    const data = new FormData(event.currentTarget);
    const submittedValues = Object.fromEntries(
      Object.keys(initialValues).map((name) => [name, String(data.get(name) ?? '')])
    ) as T;
    const nextErrors = validate(submittedValues);
    setValues(submittedValues);
    setErrors(nextErrors);
    Object.keys(initialValues).forEach((name) => touched.current.add(name));
    const invalidField = Object.keys(initialValues).find((name) => nextErrors[name]);
    if (invalidField) {
      const control = event.currentTarget.elements.namedItem(invalidField);
      if (control instanceof HTMLElement) control.focus();
      return;
    }

    inFlight.current = true;
    setStatus('pending');
    try {
      const outcome = await submit(submittedValues);
      if (!mounted.current) return;
      setStatus(outcome);
      if (outcome === 'success') {
        setValues(initialValues);
        setErrors({});
        touched.current.clear();
      }
    } catch {
      if (mounted.current) setStatus('error');
    } finally {
      inFlight.current = false;
    }
  }

  return { field, onSubmit, status, available: Boolean(submit) };
}
