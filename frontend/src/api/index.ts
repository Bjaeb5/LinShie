import axios from 'axios'

const api = axios.create({ baseURL: '/api' })

api.interceptors.request.use(cfg => {
  const token = localStorage.getItem('access_token')
  if (token) cfg.headers.Authorization = `Bearer ${token}`
  return cfg
})

api.interceptors.response.use(
  r => r,
  async err => {
    if (err.response?.status === 401) {
      localStorage.removeItem('access_token')
      window.location.href = '/login'
    }
    return Promise.reject(err)
  }
)

export default api

export const authApi = {
  login: (username: string, password: string) => {
    const form = new FormData()
    form.append('username', username)
    form.append('password', password)
    return api.post('/auth/login', form)
  },
  me: () => api.get('/auth/me'),
}

export const scansApi = {
  startLocal: () => api.post('/scans/local'),
  list: () => api.get('/scans/'),
  get: (id: number) => api.get(`/scans/${id}`),
  summary: () => api.get('/scans/stats/summary'),
}

export const hostsApi = {
  list: () => api.get('/hosts/'),
  create: (data: any) => api.post('/hosts/', data),
  update: (id: number, data: any) => api.put(`/hosts/${id}`, data),
  delete: (id: number) => api.delete(`/hosts/${id}`),
  scan: (id: number) => api.post(`/hosts/${id}/scan`),
  scans: (id: number) => api.get(`/hosts/${id}/scans`),
}

export const usersApi = {
  list: () => api.get('/users/'),
  create: (data: any) => api.post('/users/', data),
  update: (id: number, data: any) => api.put(`/users/${id}`, data),
  delete: (id: number) => api.delete(`/users/${id}`),
}

export const policiesApi = {
  list: () => api.get('/policies/'),
  create: (data: any) => api.post('/policies/', data),
  update: (id: number, data: any) => api.put(`/policies/${id}`, data),
  delete: (id: number) => api.delete(`/policies/${id}`),
  apply: (id: number, host_ids: number[]) => api.post(`/policies/${id}/apply`, { host_ids }),
  templates: () => api.get('/policies/templates'),
}
