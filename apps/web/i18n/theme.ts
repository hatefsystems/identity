// Constant source only: the request supplies a validated, bounded mode attribute,
// never interpolated executable text. CSS derives native widget color-scheme.
export const themeInitializer = "(function(){var r=document.documentElement,m=r.getAttribute('data-theme'),d=m==='dark';if(m==='system'){try{d=window.matchMedia('(prefers-color-scheme: dark)').matches===true}catch(e){d=false}}r.classList.toggle('dark',d)})()";
