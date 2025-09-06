import { Component, signal, inject } from '@angular/core';
import {
  ReactiveFormsModule, FormBuilder, Validators,
  AbstractControl, ValidationErrors, ValidatorFn
} from '@angular/forms';
import { NgIf, NgClass } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { RouterLink } from '@angular/router';

function matchFields(source: string, target: string): ValidatorFn {
  return (group: AbstractControl): ValidationErrors | null => {
    const s = group.get(source)?.value;
    const t = group.get(target)?.value;
    return s === t ? null : { fieldsMismatch: true };
  };
}

@Component({
  selector: 'app-registration',
  standalone: true,
  imports: [ReactiveFormsModule, NgIf, NgClass, RouterLink],
  templateUrl: './registration.html',
  styleUrls: ['./registration.css'],
})
export class RegistrationComponent {
  private fb = inject(FormBuilder);
  private http = inject(HttpClient);

  submitting = signal(false);
  success = signal(false);
  errorMsg = signal<string | null>(null);

  form = this.fb.group(
    {
      fullName: ['', [Validators.required, Validators.minLength(3)]],
      email: ['', [Validators.required, Validators.email]],
      password: [
        '', [
          Validators.required,
          Validators.minLength(8),
          Validators.pattern(/^(?=.*[A-Z])(?=.*\d).{8,}$/),
        ]
      ],
      confirmPassword: ['', Validators.required],
      terms: [false, Validators.requiredTrue],
    },
    { validators: matchFields('password', 'confirmPassword') }
  );

  get f() { return this.form.controls; }

  submit() {
    this.success.set(false);
    this.errorMsg.set(null);
    if (this.form.invalid) { this.form.markAllAsTouched(); return; }

    this.submitting.set(true);

    const payload = {
      fullName: this.f.fullName.value!,
      email: this.f.email.value!,
      password: this.f.password.value!,
    };

    this.http.post('http://localhost:4000/api/register', payload, { withCredentials: true }).subscribe({
      next: () => {
        this.submitting.set(false);
        this.success.set(true);
        this.form.reset();
      },
      error: (err) => {
        this.submitting.set(false);
        this.errorMsg.set(err?.error?.message || 'Registration failed');
      }
    });
  }
}
