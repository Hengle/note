# 1. 核心理念
将HTML中的DOM与JS中的对象进行绑定。
# 2. 语法
```html
<div id="app">
  <!-- 绑定数据，绑定的数据可以为表达式 -->
  {{ message }}
  {{ message + "111" }}
  <!-- 另外一种数据绑定方式，绑定的属性可以为动态参数，这个动态参数应该避免大写（使用模板时）和特殊符号 -->
  <span v-bind:title="message"></span>
  <span v-bind:[attributeName]="message"></span>
  <!-- v-bind:可以简写为: -->
  <span :title="message"></span>
  <!-- v-if指定是否渲染，不推荐同时使用 v-if 和 v-for -->
  <!-- 可以使用v-else-if和v-else指令来表示v-if的“else 块”；v-else-if和v-else元素必须紧跟在带v-if或者v-else-if的元素的后面 -->
  <span v-if="seen"></span>
  <span v-else-if="type === 'C'"></span>
  <span v-else>Now you don't</span>
  <!-- 如果几个条件分支中有同样的元素，该元素会被复用，若想指定不复用，需要给每个元素添加key属性 -->
  <template v-if="loginType === 'username'">
    <label>Username</label>
    <input placeholder="Enter your username" key="username-input">
  </template>
  <template v-else>
    <label>Email</label>
    <input placeholder="Enter your email address" key="email-input">
  </template>
  <!-- v-show指定是否展示出来（会被渲染，但是CSS中指定display为否），v-show 不支持 <template> 元素，也不支持 v-else -->
  <!-- v-show适宜于频繁切换的情况 -->
  <h1 v-show="seen">Hello!</h1>
  <!-- 循环一个数组或者对象，最好提供key，以便追踪索引 -->
  <!-- 数组可以使用计算属性和方法来代替 -->
  <!-- 对象可以同时遍历值、名称、索引<div v-for="(value, name, index) in object"> -->
  <!-- 可以访问父属性attributeName -->
  <!-- in可以替换成of -->
  <!-- template和组件中也可以使用v-for -->
  <ol>
    <li v-for="(item, index) in todos" v-bind:key="item.id">
      {{ todo.text }} - {{ attributeName }} - {{}}
    </li>
  </ol>
  <!-- 事件 -->
  <button v-on:click="reverseMessage">反转消息</button>
  <!-- 指出一个指令应该以特殊方式绑定，如，.prevent 修饰符告诉 v-on 指令对于触发的事件调用 event.preventDefault() -->
  <form v-on:submit.prevent="onSubmit">...</form>
  <!-- v-on:可以简写为@ -->
  <!-- 可以添加参数，可以使用原生事件参数$event -->
  <button @click="reverseMessage">反转消息</button>
  <!-- 事件可以添加修饰符，修饰符可以串联 -->
  <a v-on:click.stop.prevent="doThat"></a>
  <!-- 点击事件将只会触发一次 -->
  <a v-on:click.once="doThis"></a>
  <!-- 键盘事件，可以用如下修饰符来实现仅在按下相应按键时才触发鼠标或键盘事件的监听器。.ctrl.alt.shift.meta -->
  <input v-on:keyup.page-down="onPageDown">
  <!-- 表单 -->
  <!-- 多选框和多选列表，可以绑定到数组 -->
  <!-- .number等修饰符 -->
  <input v-model="message">
  <!-- 一次性插值，当数据改变时，插值处的内容不会更新 -->
  <span v-once>这个将不会改变: {{ message }}</span>
  <!-- 将rawHtml变量的值解释为HTML代码 -->
  <p>Using v-html directive: <span v-html="rawHtml"></span></p>
</div>
```
```js
var app = new Vue({
  el: '#app',
  data: {
    message: 'Hello Vue!',
    attributeName: 'title',
    seen: true,
    todos: [
      { text: '学习 JavaScript' },
      { text: '学习 Vue' },
      { text: '整个牛项目' }
    ]
  },
  methods: {
    reverseMessage: function () {
      this.message = this.message.split('').reverse().join('')
    }
  }
})
```
# 3. 组件
```html
<div id="app-7">
  <blog-post
  v-for="post in posts"
  v-bind:post="post"
  v-on:enlarge-text="onEnlargeText"
></blog-post>
</div>
```
```js
// 注册组件
// props为外界传入数据
// data为内部数据
// 模板内部只能有一个根元素
// 子组件可以和父组件通信，$event可以传递参数
Vue.component('blog-post', {
  props: ['post'],
  data: function () {
    return {
      count: 0
    }
  },
  template: `
  <div :style="{ fontSize: postFontSize + 'em' }">
    <h3>{{ count }}</h3>
    <h3>{{ post.id }}</h3>
    <h3>{{ post.title }}</h3>
    <button v-on:click="$emit('enlarge-text, 0.1')">Enlarge text</button>
    <button v-on:click="count++">Enlarge text</button>
  </div>
  `
})
var app7 = new Vue({
  el: '#app-7',
  data: {
    posts: [
      { id: 1, title: 'My journey with Vue' },
      { id: 2, title: 'Blogging with Vue' },
      { id: 3, title: 'Why Vue is so fun' }
    ],
    postFontSize: 1
  },
  methods: {
    onEnlargeText: function (enlargeAmount) {
      this.postFontSize += enlargeAmount
    }
  }
})
//v-model
//插槽
//动态组件
//解析 DOM 模板时，有些 HTML 元素，诸如 <ul>、<ol>、<table> 和 <select>，对于哪些元素可以出现在其内部是有严格限制的。而有些元素，诸如 <li>、<tr> 和 <option>，只能出现在其它某些特定的元素内部
```
# 4. VUE实例
```js
var data = { a: 1 }
var vm = new Vue({
  el: '#example',
  data: data
})
// $前缀代表访问自身属性而非绑定的数据的属性
vm.$data === data // => true
vm.$el === document.getElementById('example') // => true
// Object.freeze()可以冻结对象，使得对象不得改变，视图不会和对象保持同步修改
Object.freeze(data)
```
# 5. 钩子函数
在一个VUE实例的生命周期中，可以插入钩子函数，比如created钩子可以用来在一个实例被创建之后执行代码。
```js
new Vue({
  data: {
    a: 1
  },
  created: function () {
    // `this` 指向 vm 实例
    console.log('a is: ' + this.a)
  }
})
// => "a is: 1"
```
# 6. 计算属性
计算属性可以绑定计算性质的属性（双向绑定get和set），可以简化重复操作，另外相比较于Methons，计算属性会保留缓存，频繁调用数据时，计算属性性能更优异
```html
<div id="example">
  <p>Original message: "{{ message }}"</p>
  <p>Computed reversed message: "{{ reversedMessage }}"</p>
</div>
```
```js
var vm = new Vue({
  el: '#example',
  data: {
    message: 'Hello'
  },
  computed: {
    fullName: {
      // getter
      get: function () {
        return this.firstName + ' ' + this.lastName
      },
      // setter
      set: function (newValue) {
        var names = newValue.split(' ')
        this.firstName = names[0]
        this.lastName = names[names.length - 1]
      }
    }
  }
  // 默认情况下为getter
  computed: {
    fullName: function () {
      return this.firstName + ' ' + this.lastName
    }
  }
})
```
# 7. 侦听器
Vue 通过 watch 选项提供了一个更通用的方法，来响应数据的变化。
```html
<div id="watch-example">
  <p>
    Ask a yes/no question:
    <input v-model="question">
  </p>
  <p>{{ answer }}</p>
</div>
```
```js
var watchExampleVM = new Vue({
  el: '#watch-example',
  data: {
    question: '',
    answer: 'I cannot give you an answer until you ask a question!'
  },
  watch: {
    // 如果 `question` 发生改变，这个函数就会运行
    question: function (newQuestion, oldQuestion) {
      this.answer = 'Waiting for you to stop typing...'
    }
  },
})
```
组件的prop应该为单向数据流，子组件不应该改变prop的值，从而影响父组件
子组件给父组件传输数据可以使用自定义事件或者.sync
